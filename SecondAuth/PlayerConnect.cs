using MEC;
using Smod2.API;
using MaxMind.GeoIP2;
using System;
using System.Net;
using Smod2.EventHandlers;
using Smod2.Events;
using UnityEngine.Networking;
using System.Collections;
using System.Collections.Generic;
using Newtonsoft.Json;
using MaxMind.GeoIP2.Exceptions;
using MaxMind.GeoIP2.Responses;

namespace SecondAuth
{
    internal class PlayerConnect : IEventHandlerConnect
    {
        private SecondAuth secondAuth;
        public PlayerConnect(SecondAuth secondAuth) => this.secondAuth = secondAuth;

        public void OnConnect(ConnectEvent ev)
        {
            if (ev.Connection.IpAddress == "localClient") return;

            //if (secondAuth.antiUnauthed > -1) Timing.RunCoroutine(CheckIsAuthenticated(ev));

            if (Array.IndexOf(secondAuth.blacklistedAsnList, secondAuth.ASNDatabase.Asn(ev.Connection.IpAddress).AutonomousSystemNumber) > -1)
            {
                ev.Connection.Disconnect();

                secondAuth.Info($"The connection from {ev.Connection.IpAddress} was terminated due to connecting from a blacklisted ASN");

                if (secondAuth.blacklistedAsn > 0 && secondAuth.ipBanning)
                {
                    secondAuth.Server.BanIpAddress("Unknown player", ev.Connection.IpAddress, secondAuth.blacklistedAsn, "Connecting from a blacklisted ASN", secondAuth.Details.name);
                }
            }
        }

        private IEnumerator<float> CheckIsAuthenticated(ConnectEvent ev)
        {
            yield return Timing.WaitForSeconds(secondAuth.timeoutKick);

            int playerint = secondAuth.Server.GetPlayers().FindIndex(plr => plr.IpAddress == ev.Connection.IpAddress);

            if (!(playerint > -1))
            {
                ev.Connection.Disconnect();

                if (secondAuth.antiUnauthed > 0) secondAuth.Server.BanIpAddress("", ev.Connection.IpAddress, secondAuth.antiUnauthed, "Connected too long without authenticating", secondAuth.Details.name);
            }
        }
    }
}