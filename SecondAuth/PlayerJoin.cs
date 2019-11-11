using MEC;
using Smod2.API;
using MaxMind.GeoIP2;
using System;
using System.Net;
using System.Text;
using Smod2.EventHandlers;
using Smod2.Events;
using UnityEngine.Networking;
using System.Collections;
using System.Collections.Generic;
using Newtonsoft.Json;
using MaxMind.GeoIP2.Exceptions;
using MaxMind.GeoIP2.Responses;
using System.Text.RegularExpressions;
using System.IO;
using UnityEngine;

namespace SecondAuth
{
    internal class PlayerJoin : IEventHandlerPlayerJoin, IEventHandlerSceneChanged
    {
        private SecondAuth secondAuth;
        public PlayerJoin(SecondAuth secondAuth) => this.secondAuth = secondAuth;

        public bool JoinQueueWorking = false;
        public Queue JoinQueue = new Queue();

        #region PlayerJoin

        public void OnPlayerJoin(PlayerJoinEvent ev)
        {
            if (((GameObject)ev.Player.GetGameObject()).GetComponent<ServerRoles>().BypassStaff) return;

            else if (((GameObject)ev.Player.GetGameObject()).GetComponent<ServerRoles>().BypassStaff
                || Array.IndexOf(secondAuth.whitelistedSteamIds, "\"" + ev.Player.SteamId + "\"") > -1 || Array.IndexOf(secondAuth.whitelistedIps, "\"" + ev.Player.IpAddress.Replace("::ffff:", string.Empty) + "\"") > -1)
            {
                secondAuth.Info($"{ev.Player.Name} is whitelisted, so has been skipped");
                return;
            }

            if (!AntiDupe(ev.Player))
            {
                if (!JoinQueue.Contains(ev.Player))
                {
                    JoinQueue.Enqueue(ev.Player);
                    if (!JoinQueueWorking) HandleQueue();
                }
            }
        }

        internal void HandleQueue()
        {
            while (JoinQueue.Count > 0)
            {
                Player player = (Player)JoinQueue.Peek();

                if (secondAuth.apiToken != string.Empty) Timing.WaitUntilDone(SteamQuery(player));
                if (player.IpAddress != "127.0.0.1") Timing.WaitUntilDone(IPCheck(player));
                if (secondAuth.advancedIpLogging) Timing.WaitUntilDone(CheckAccounts(player));

                JoinQueue.Dequeue();
            }

            secondAuth.Info("Saving account data...");

            string IpAccounts = Path.Combine(FileManager.GetAppFolder(true), "SecondAuthAccounts.json");

            using (StreamWriter w = new StreamWriter(IpAccounts))
            {
                try
                {
                    w.Write(JsonConvert.SerializeObject(ipAccountsList));
                }
                catch (Exception e)
                {
                    secondAuth.Error($"There was an error saving the IP accounts list: " + e.Message);
                }
            }
        }

        #region AntiDupe

        LastJoin lastJoin = new LastJoin();
        public class LastJoin
        {
            public string AuthToken { get; set; }
            public DateTime LastTime { get; set; }
        }

        private bool AntiDupe(Player player)
        {
            if ((DateTime.Now - lastJoin.LastTime).TotalSeconds > secondAuth.antiDupeCatch)
            {
                lastJoin.AuthToken = player.GetAuthToken();
                lastJoin.LastTime = DateTime.Now;

                return false;
            }
            else
            {
                if (lastJoin.AuthToken == player.GetAuthToken())
                {
                    HandleDC(player, secondAuth.antiDupe, "Duplicate account detected");
                    return true;
                }
                else
                {
                    lastJoin.AuthToken = player.GetAuthToken();
                    lastJoin.LastTime = DateTime.Now;

                    return false;
                }
            }
        }

        #endregion

        #region Steam Query

        #region Steam Query Objects
        public class QueryAccount
        {
            public string steamid { get; set; }
            public int communityvisibilitystate { get; set; }
            public int profilestate { get; set; }
            public string personaname { get; set; }
            public int lastlogoff { get; set; }
            public int commentpermission { get; set; }
            public string profileurl { get; set; }
            public string avatar { get; set; }
            public string avatarmedium { get; set; }
            public string avatarfull { get; set; }
            public int personastate { get; set; }
            public string primaryclanid { get; set; }
            public int timecreated { get; set; }
            public int personastateflags { get; set; }
            public string loccountrycode { get; set; }
        }
        public class Response
        {
            public List<QueryAccount> players { get; set; }
        }
        public class RootObject
        {
            public Response response { get; set; }
        }
        #endregion

        private IEnumerator<float> SteamQuery(Player player)
        {
            UnityWebRequest www = new UnityWebRequest($"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={secondAuth.apiToken}&steamids={player.SteamId}");
            www.downloadHandler = new DownloadHandlerBuffer();

            yield return Timing.WaitUntilDone(www.SendWebRequest());
            if (www.isNetworkError || www.isHttpError) { secondAuth.Error($"There has was an error contacting the Steam web API: {www.error}\nError code:{www.responseCode}"); yield return 1f; }
            else
            {
                RootObject rootObject = JsonConvert.DeserializeObject<RootObject>(www.downloadHandler.text);
                QueryAccount steamaccount = rootObject.response.players[0];

                if (!(secondAuth.profileNotSetLength < 0) && steamaccount.profilestate == 0) HandleDC(player, secondAuth.profileNotSetLength, "Profile not set up");
                else if (steamaccount.timecreated != 0 && ((DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0).AddSeconds(steamaccount.timecreated)).TotalHours < secondAuth.minimumAccountAge)) HandleDC(player, secondAuth.newAccount, "Account is too new");
                else
                {
                    foreach (string word in secondAuth.blacklistedWordsList)
                    {
                        if (player.Name.ToLower().Contains(word.ToLower())) HandleDC(player, secondAuth.blacklistedWords, "Blacklisted word/character");
                    }
                }
            }

            www.Dispose();

            yield return 1f;
        }

        #endregion

        #region IP Query

        public class IpInfo
        {
            public CountryResponse country { get; set; }
            public AsnResponse asn { get; set; }
        }

        private IEnumerator<float> IPCheck(Player player)
        {
            IpInfo ConnInfo = GetAsn(player.IpAddress);
            IpInfo AuthInfo = GetAsn(player.GetAuthToken().Split(new[] { "<br>" }, StringSplitOptions.RemoveEmptyEntries)[2].Replace("Request IP: ", string.Empty));

            if (ConnInfo == null || AuthInfo == null) yield return 1f;

            if (secondAuth.asnDiscrepancy >= 0 && (ConnInfo.asn.AutonomousSystemNumber != AuthInfo.asn.AutonomousSystemNumber)) HandleDC(player, secondAuth.asnDiscrepancy, "ASN Discrepancy between connection and authentication IPs");
            else if (secondAuth.asnCountryDiscrepancy >= 0 && (ConnInfo.country.Country.IsoCode != AuthInfo.country.Country.IsoCode)) HandleDC(player, secondAuth.asnCountryDiscrepancy, "Discrepency between connection and authentication countries");
            else if (secondAuth.asnContinentDiscrepancy >= 0 && (ConnInfo.country.Continent.Code != AuthInfo.country.Continent.Code)) HandleDC(player, secondAuth.asnContinentDiscrepancy, "Discrepency between connection and authentication continents");
            else if (Array.IndexOf(secondAuth.blacklistedAsnList, ConnInfo.asn.AutonomousSystemNumber) > -1) HandleDC(player, secondAuth.blacklistedAsn, $"Connecting from a blacklisted ASN");
            else if (Array.IndexOf(secondAuth.blacklistedAsnList, AuthInfo.asn.AutonomousSystemNumber) > -1) HandleDC(player, secondAuth.blacklistedAsn, $"Authenticating from a blacklisted ASN");

            yield return 1f;
        }

        private IpInfo GetAsn(string ip)
        {
            try
            {
                return new IpInfo()
                {
                    country = secondAuth.CountryDatabase.Country(ip),
                    asn = secondAuth.ASNDatabase.Asn(ip),
                };
            }
            catch (AddressNotFoundException)
            {
                secondAuth.Error($"{ip} was unable to be found in one of the databases. You can download the most recent copies of the Country and ASN databases at: https://dev.maxmind.com/geoip/geoip2/geolite2/");
                return null;
            }
        }

        #endregion

        #region Advanced IP Logging

        public class AILAccount
        {
            public string name { get; set; }
            public string steamid { get; set; }
        }
        public class IpAccounts
        {
            public string ipAddress { get; set; }
            public List<AILAccount> accounts { get; set; }
        }

        internal List<IpAccounts> ipAccountsList = new List<IpAccounts>();

        Regex rgx = new Regex("[^a-zA-Z0-9 -]");

        internal IEnumerator<float> CheckAccounts(Player player)
        {
            int ipIndex = ipAccountsList.FindIndex(ip => ip.ipAddress == player.IpAddress);

            //If the IP exists
            if (ipIndex > -1)
            {
                int accountIndex = ipAccountsList[ipIndex].accounts.FindIndex(account => account.steamid == player.SteamId);

                if (accountIndex > -1)
                {
                    //If account exists within IP
                    ipAccountsList[ipIndex].accounts[accountIndex].name = rgx.Replace(player.Name, string.Empty);
                }
                else
                {
                    //If account does NOT exist within IP

                    if (ipAccountsList[ipIndex].accounts.Count + 1 > secondAuth.accountLimit) HandleAILDC(player, secondAuth.accountLimitTime, "Too many accounts from the same IP address");
                    else
                    {
                        ipAccountsList[ipIndex].accounts.Add(new AILAccount { name = rgx.Replace(player.Name, string.Empty), steamid = player.SteamId });
                    }
                }
            }
            else
            {
                ipAccountsList.Add(new IpAccounts
                {
                    ipAddress = player.IpAddress,
                    accounts = new List<AILAccount>{
                        new AILAccount{
                            name = rgx.Replace(player.Name, string.Empty),
                            steamid = player.SteamId
                        }
                    }
                });
            }

            yield return 1f;
        }

        internal void HandleAILDC(Player player, int length, string message)
        {
            player.Disconnect($"SecondAuth has {(length == 0 ? "kicked" : "banned")} you from the server"
                + $"{(!secondAuth.detailedMessage ? "" : $"\nReason: { message}")}"
                + $"\nNote: This action was automatically performed by a plugin.");

            secondAuth.Info($"{player.Name} was {(length == 0 ? "kick" : "banned")} from the server. Reason: {message}");

            if (length > 0)
            {
                secondAuth.Server.BanSteamId(player.Name, player.SteamId, length, message, secondAuth.Details.name);
            }
        }


        public void OnSceneChanged(SceneChangedEvent ev)
        {
            secondAuth.Info("Refreshing saved accounts data...");
            if (secondAuth.advancedIpLogging)
            {
                string IpAccounts = Path.Combine(FileManager.GetAppFolder(true), "SecondAuthAccounts.json");
                if (File.Exists(IpAccounts))
                {
                    using (StreamReader r = new StreamReader(IpAccounts))
                    {
                        ipAccountsList = JsonConvert.DeserializeObject<List<IpAccounts>>(r.ReadToEnd());
                    }
                }
            }
        }

        #endregion

        #endregion

        internal void HandleDC(Player player, int length, string message)
        {
            player.Disconnect($"SecondAuth has {(length == 0 ? "kicked" : "banned")} you from the server"
                + $"{(!secondAuth.detailedMessage ? "" : $"\nReason: { message}")}"
                + $"\nNote: This action was automatically performed by a plugin.");

            secondAuth.Info($"{player.Name} was {(length == 0 ? "kick" : "banned")} from the server. Reason: {message}");

            if (length > 0)
            {
                secondAuth.Server.BanSteamId(player.Name, player.SteamId, length, message, secondAuth.Details.name);
                if (secondAuth.ipBanning) secondAuth.Server.BanIpAddress(player.Name, player.IpAddress, length, message, secondAuth.Details.name);
            }
        }
    }
}