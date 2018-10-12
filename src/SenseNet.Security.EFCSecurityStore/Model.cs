using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace SenseNet.Security.EFCSecurityStore
{
    internal static class ExecutionState
    {
        public const string Wait = "Wait";
        public const string Executing = "Executing";
        public const string Done = "Done";
        public const string LockedForYou = "LockedForYou";
    }

    /* ======================================== regular entities */

    internal class EFEntity
    {
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        [Key]
        public int Id { get; set; }
        public int? OwnerId { get; set; }
        public int? ParentId { get; set; }
        public bool IsInherited { get; set; }

        public virtual EFEntity Parent { get; set; }
        public virtual List<EFEntity> Children { get; set; }

        public virtual List<EFEntry> EFEntries { get; set; }
    }
    internal class EFEntry
    {
        public int EFEntityId { get; set; } // Key member
        public int EntryType { get; set; } // Key member
        public int IdentityId { get; set; } // Key member
        public bool LocalOnly { get; set; } // Key member
        public long AllowBits { get; set; }
        public long DenyBits { get; set; }

        public virtual EFEntity EFEntity { get; set; }

        /// <summary>Tests use this method. DO NOT REMOVE.</summary>
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        public override string ToString()
        {
            var chars = new char[PermissionTypeBase.PermissionCount];
            for (var i = 0; i < PermissionTypeBase.PermissionCount; i++)
            {
                var mask = 1ul << i;
                if ((DenyBits & (long)mask) != 0)
                    chars[PermissionTypeBase.PermissionCount - i - 1] = '-';
                else if ((AllowBits & (long)mask) != 0)
                    chars[PermissionTypeBase.PermissionCount - i - 1] = '+';
                else
                    chars[PermissionTypeBase.PermissionCount - i - 1] = '_';
            }
            return $"({EFEntityId})|{EntryType}|{(LocalOnly ? "-" : "+")}({IdentityId}):{new string(chars)}";
        }

        public StoredAce ToStoredAce()
        {
            return new StoredAce
            {
                EntityId = this.EFEntityId,
                EntryType = (EntryType)this.EntryType,
                IdentityId = this.IdentityId,
                LocalOnly = this.LocalOnly,
                AllowBits = this.AllowBits.ToUInt64(),
                DenyBits = this.DenyBits.ToUInt64()
            };
        }
    }
    internal class EFMembership
    {
        public int GroupId { get; set; } // Key member
        public int MemberId { get; set; } // Key member
        public bool IsUser { get; set; }
    }
    internal class EFMessage
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string SavedBy { get; set; }
        public DateTime SavedAt { get; set; }
        public string ExecutionState { get; set; } // null, Executing, Done
        public string LockedBy { get; set; }
        public DateTime? LockedAt { get; set; }
        public byte[] Body { get; set; }
    }

    /* ======================================== query types */

    internal class EfcIntItem
    {
        [Key]
        public int Id { get; set; }
        public int Value { get; set; }
    }
    internal class EfcStringItem
    {
        [Key]
        public int Id { get; set; }
        public string Value { get; set; }
    }

    internal class EfcStoredSecurityEntity
    {
        [Key]
        public int Id { get; set; }
        public int? nullableOwnerId { get; set; }
        public int? nullableParentId { get; set; }
        public bool IsInherited { get; set; }
        public bool HasExplicitEntry { get; set; }
    }

}
