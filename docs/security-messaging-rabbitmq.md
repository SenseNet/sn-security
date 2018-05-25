---
title: "RabbitMQ security message provider"
source_url: 'https://github.com/SenseNet/sn-security/blob/master/docs/security-messaging-rabbitmq.md'
category: Development
version: v1.0.0
tags: [messaging, cloud, provider, sn7]
description: Details on the RabbitMQ security messaging provider for the sensenet platform.
---

# RabbitMQ security message provider
[RabbitMQ](https://www.rabbitmq.com) implementation for sending **server-to-server** messages in the **security component**.

In case you work with multiple web servers in a load balanced environment, a centralized search service or any other distributed component, you will need some kind of messaging to notify other app domains about changes. The messaging module lets your separate server components communicate with each other.

> Please note that this messaging is not about sending notifications to the client - it is intended to send messages to _other app domains_ connecting to the same database. If you are using sensenet, this provider can be used in conjunction with the [main RabbitMQ messaging provider](https://community.sensenet.com/docs/messaging-rabbitmq) that is responsible for handling general server-to-server messages (as opposed to this one which is for sending *security-related* messages).

The **RabbitMQ** implementation targets the widely used RabbitMQ message broker. The advantage of using a service is that you only have to configure a single URL, the RabbitMQ client (represented by this provider) will connect to the service and will send and receive messages to and from all other components that are connected to the same service on the same _exchange_ (see below).

## Installation
To get started, install the following NuGet package:

[![NuGet](https://img.shields.io/nuget/v/SenseNet.Security.Messaging.RabbitMQ.svg)](https://www.nuget.org/packages/SenseNet.Security.Messaging.RabbitMQ)

## Usage
To use this provider you have to instantiate it in your application and provide one or more parameters as shown in the sections below.

### Service url
The **service url** mandatory parameter contains the [RabbitMQ URI](http://rabbitmq.github.io/rabbitmq-dotnet-client/api/RabbitMQ.Client.ConnectionFactory.html) to connect to.

```csharp
var smp = new RabbitMQMessageProvider("amqp://abcd:example.com/defg");
smp.Initialize();
```

> Please note that you have to call the `Initialize` method before using the provider.

### Exchange name
In case you want to use the same RabbitMQ service for **multiple different application instances** (e.g. both in test and staging environments), you need to provide a **unique exchange name** for each instance. Please make sure you use the same exchange name in every app domain (e.g. web server) that uses the same Content Repository and need to communicate with each other.

```csharp
var smp = new RabbitMQMessageProvider("amqp://abcd:example.com/defg",
   "sn-securitymessage-test.example.com");
smp.Initialize();
```

### Setting the provider in sensenet
In case you are using this provider with sensenet you have to set it as the security message provider the following way during [application or repository start](https://community.sensenet.com/docs/configure-repository).

```csharp
repositoryBuilder.UseSecurityMessageProvider(smp);
```

> Please note that you have to call the `Initialize` method before using the provider.