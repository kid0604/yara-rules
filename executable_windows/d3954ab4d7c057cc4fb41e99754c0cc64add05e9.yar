import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_DiscordURL
{
	meta:
		author = "ditekSHen"
		description = "Detects executables Discord URL observed in first stage droppers"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "https://discord.com/api/webhooks/" ascii wide nocase
		$s2 = "https://cdn.discordapp.com/attachments/" ascii wide nocase
		$s3 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va" ascii wide
		$s4 = "aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobW" ascii wide
		$s5 = "/skoohbew/ipa/moc.drocsid//:sptth" ascii wide nocase
		$s6 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii wide nocase
		$s7 = "av9GaiV2dvkGch9SbvNmLkJ3bjNXak9yL6MHc0RHa" ascii wide
		$s8 = "WboNWY0RXYv02bj5CcwFGZy92YzlGZu4GZj9yL6MHc0RHa" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}
