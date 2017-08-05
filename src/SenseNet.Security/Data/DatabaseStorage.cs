using System;
using System.Collections.Generic;

namespace SenseNet.Security.Data
{
    public class Membership
    {
        public int GroupId { get; set; } // Key member
        public int MemberId { get; set; } // Key member
        public bool IsUser { get; set; }
    }

    /// <summary>
    /// Simulates a data of any database
    /// </summary>
    public class DatabaseStorage
    {
        public Dictionary<int, StoredSecurityEntity> Entities;
        public List<Membership> Memberships;
        public List<StoredAce> Aces;

        /// <summary>Id, SavedAt, Body</summary>
        public List<Tuple<int, DateTime, byte[]>> Messages;

        public static DatabaseStorage CreateEmpty()
        {
            return new DatabaseStorage
            {
                Aces = new List<StoredAce>(),
                Entities = new Dictionary<int, StoredSecurityEntity>(),
                Memberships = new List<Membership>(),
                Messages = new List<Tuple<int,DateTime,byte[]>>()
            };
        }
    }
}
