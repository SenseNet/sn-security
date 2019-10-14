# sensenet Security

[![Join the chat at https://gitter.im/SenseNet/sn-security](https://badges.gitter.im/SenseNet/sn-security.svg)](https://gitter.im/SenseNet/sn-security?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Security core](https://img.shields.io/nuget/v/SenseNet.Security.svg)](https://www.nuget.org/packages/SenseNet.Security)
[![EF/ data provider](https://img.shields.io/nuget/v/SenseNet.Security.EF6SecurityStore.svg)](https://www.nuget.org/packages/SenseNet.Security.EF6SecurityStore)
[![MSMQ message provider](https://img.shields.io/nuget/v/SenseNet.Security.Messaging.Msmq.svg)](https://www.nuget.org/packages/SenseNet.Security.Messaging.Msmq)

A powerful and fast .Net component for managing **permission entries** in structured content repositories.

The permission layer of [sensenet](https://github.com/SenseNet/sensenet) is built on top of this library, so it is a well-tested, robust and scalable option for providing permission features in large projects.

Permission entries and user-group relationships are stored in a database that can be replaced with a **custom db provider**. The built-in db provider is for *Entity Framework*.

## Main features
### Entities
The security component has an API for maintaining an entity structure (parent-child relationships), so it is ideal and most effective for providing security functionality in environments where there is a tree structure.
````csharp
// register an entity in the security component
context.CreateSecurityEntity(entityId, parentId, ownerId);
````
### Users and Groups
User-Group relationships are essential, because permissions are evaluated in a transitive way: permissions set for a group apply to its members too. Groups may have group members too.
````csharp
context.IsInGroup(memberId, groupId);
````
### Entries
Permission entries (*Access Control Entries*) are lists of permissions defined on an entity for a user or group. The security component handles permissions as simple slots in the db, the permission types (e.g. Open or Save) are defined by the client application.
````csharp
// break permission inheritance, fluent API
context.CreateAclEditor()
	.BreakInheritance(entityId1)
	.Allow(entityId2, identityId1, localOnly, PermissionType.Save)
	.Allow(entityId3, identityId2, localOnly, PermissionType.AddNew)
	.Apply();
````
## Evaluation
Permission evaluation takes two things into account:
- **tree structure**: permissions defined on the parent are applied on children (unless they are local-only).
- **group memberships**: permissions set for a group apply to all group members.

It works similarly to *file system permissions*, in other words: *it works as you expect*.

````csharp
// permission check for a single item
if (context.HasPermission(entityId, PermissionType.See)) 
{
}
````

## Integration

For details on integrating it in a 3rd party application please visit the following article:
- http://wiki.sensenet.com/Security_Component
