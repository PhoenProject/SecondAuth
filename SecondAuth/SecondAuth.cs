using Smod2;
using MEC;
using Smod2.API;
using Smod2.Config;
using Smod2.Attributes;
using MaxMind.GeoIP2;
using System.IO;
using System;
using System.Net;
using Smod2.EventHandlers;
using Smod2.Events;
using UnityEngine;
using UnityEngine.Networking;
using UnityEngine.Networking.NetworkSystem;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace SecondAuth
{
    [PluginDetails(
    author = "Phoenix",
    configPrefix = "sa",
    description = "Adds secondary authentication to your server, allowing you to add more specific blocking to users that join the server",
    id = "phoenix.secondauth",
    name = "SecondAuth",
    version = "1.0b",
    SmodMajor = 3,
    SmodMinor = 5,
    SmodRevision = 0
    )]

    public class SecondAuth : Plugin
    {
        #region Configs

        //Should SecondAuth IP ban aswell as account ban
        [ConfigOption]
        internal readonly bool ipBanning = true;

        //Should SecondAuth tell the user why they have been banned/disconnected (Reason will ALWAYS be printed to the server console, and as the reason for bans if enabled)
        [ConfigOption]
        internal readonly bool detailedMessage = false;

        //Steam web API token (Get it from https://steamcommunity.com/dev)
        [ConfigOption]
        internal readonly string apiToken = string.Empty;

        //Advanced IP logging. If an IP address has too many users connecting from it, it will block all connections from new accounts (Experimental)
        [ConfigOption]
        //internal bool advancedIpLogging = false;
        internal bool advancedIpLogging = true;
        [ConfigOption]
        internal readonly int accountLimit = 2;
        [ConfigOption]
        internal readonly int accountLimitTime = 30000000; //57 years

        //Ban length (in minutes) for checks triggered. 0 kicks, 1 or more is length, -1 to disable

        //Ban length for users who's profiles are not set up
        [ConfigOption]
        internal readonly int profileNotSetLength = 0; //Kicks

        //Steam profile age (in hours)
        [ConfigOption]
        internal readonly int minimumAccountAge = 72; //Account must be at least 3 days old
        [ConfigOption]
        internal readonly int newAccount = 10080; //7 days

        //Blacklisted word check (Also doubles as a name check
        [ConfigOption]
        internal readonly string[] blacklistedWordsList = { };
        [ConfigOption]
        internal readonly int blacklistedWords = 10080; //7 days

        //ASN discrepancy
        [ConfigOption]
        internal readonly int asnDiscrepancy = -1;
        [ConfigOption]
        internal readonly int asnCountryDiscrepancy = 43200; //30 days
        [ConfigOption]
        internal readonly int asnContinentDiscrepancy = 30000000; //57 years

        //Blacklisted ASNs
        [ConfigOption]
        internal readonly int[] blacklistedAsnList = { };
        [ConfigOption]
        internal readonly int blacklistedAsn = 43200; //30 days

        //Anti-Dupe (Stops a user from authenticating twice within a short period of time)
        [ConfigOption]
        internal readonly int antiDupeCatch = 1; //3 second catch time
        [ConfigOption]
        internal readonly int antiDupe = 30000000; //57 years

        //Anti-UnAuthed (Stops users from staying connected to the server once they fail to authenticate)
        [ConfigOption]
        internal readonly int antiUnauthed = 0; //Kick
        [ConfigOption]
        internal readonly float timeoutKick = 25; //15 seconds

        [ConfigOption]
        internal readonly string[] whitelistedSteamIds = { };
        [ConfigOption]
        internal readonly string[] whitelistedIps = { };

        #endregion

        public DatabaseReader ASNDatabase { get; private set; }
        public DatabaseReader CountryDatabase { get; private set; }

        public override void OnDisable()
        {
            Info(Details.name + " was disabled!");
        }

        public override void OnEnable()
        {
            string ASN = Path.Combine(FileManager.GetAppFolder(true), "GeoIP2-ASN.mmdb");
            if (!File.Exists(ASN))
            {
                Error($"GeoIP2-ASN database not found. Expected database at: {ASN}"
                    + $"\nYou can download this database from https://dev.maxmind.com/geoip/geoip2/geolite2/");
                PluginManager.Manager.DisablePlugin(this);
                return;
            }

            string Country = Path.Combine(FileManager.GetAppFolder(true), "GeoIP2-Country.mmdb");
            if (!File.Exists(Country))
            {
                Error($"GeoIP2-Country database not found. Expected database at: {Country}"
                    + $"\nYou can download this database from https://dev.maxmind.com/geoip/geoip2/geolite2/");

                PluginManager.Manager.DisablePlugin(this);
                return;
            }

            ASNDatabase = new DatabaseReader(ASN);
            CountryDatabase = new DatabaseReader(Country);

            Info(Details.name + " was enabled!");
        }

        public override void Register()
        {
            AddEventHandlers(new PlayerJoin(this));
            AddEventHandlers(new PlayerConnect(this));
        }
    }
}