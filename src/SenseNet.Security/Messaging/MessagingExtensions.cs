﻿using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using SenseNet.Security.Messaging.SecurityMessages;

namespace SenseNet.Security.Messaging
{
    public static class MessagingExtensions
    {
        public static IServiceCollection AddSecurityMessageType<T>(this IServiceCollection services) where T : IDistributedMessage
        {
            return services.AddSingleton<DistributedMessageType>(new DistributedMessageType(typeof(T)));
        }
        public static IServiceCollection AddDefaultSecurityMessageTypes(this IServiceCollection services)
        {
            return services
                    // IDistributedMessage
                    .AddSecurityMessageType<UnknownMessage>()
                    // DistributedMessage
                    .AddSecurityMessageType<BigActivityMessage>()
                    // DebugMessage
                    .AddSecurityMessageType<DebugMessage>()
                    .AddSecurityMessageType<PingMessage>()
                    .AddSecurityMessageType<PongMessage>()
                    // SecurityActivity
                    .AddSecurityMessageType<CreateSecurityEntityActivity>()
                    .AddSecurityMessageType<DeleteSecurityEntityActivity>()
                    .AddSecurityMessageType<ModifySecurityEntityOwnerActivity>()
                    .AddSecurityMessageType<MoveSecurityEntityActivity>()
                    .AddSecurityMessageType<SetAclActivity>()
                    // MembershipActivity
                    .AddSecurityMessageType<AddUserToSecurityGroupsActivity>()
                    .AddSecurityMessageType<AddMembersToGroupActivity>()
                    .AddSecurityMessageType<RemoveUserFromSecurityGroupsActivity>()
                    .AddSecurityMessageType<RemoveMembersFromGroupActivity>()
                    .AddSecurityMessageType<DeleteUserActivity>()
                    .AddSecurityMessageType<DeleteIdentitiesActivity>()
                    .AddSecurityMessageType<DeleteGroupActivity>()
                ;
        }
    }
}
