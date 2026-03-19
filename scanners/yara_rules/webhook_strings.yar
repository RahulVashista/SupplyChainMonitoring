rule webhook_strings
{
  strings:
    $discord = "discord.com/api/webhooks" ascii nocase
    $telegram = "api.telegram.org/bot" ascii nocase
    $paste = "pastebin.com/raw" ascii nocase
  condition:
    any of them
}
