# Owin.Security.Providers.Trello

A Trello OAuth provider for OWIN to use with ASP.NET.

## Installation

NuGet package coming soon.

## Usage

NOTE: A Trello API key is required for this to work. Refer to the [Trello documentation](https://trello.com/docs/gettingstarted/index.html#getting-an-application-key) for instructions on how to get an API key. 

In your `Startup.Auth.cs` add the following using statement:

    using Owin.Security.Providers.Trello;

Then in the `ConfigureAuth` method enable the Trello provider:

    app.UseTrelloAuthentication(
        key: "YourTrelloApiKey",
        secret: "YourTrelloApiSecret",
        appName: "My App");