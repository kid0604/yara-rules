import "dotnet"

rule win_njrat_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = ""
		sha_256 = "59d6e2958780d15131c102a93fefce6e388e81da7dc78d9c230aeb6cab7e3474"
		sha_256 = "4c56ade4409add1d78eac3b202a9fbd6afbd71878c31f798026082467ace2628"
		sha_256 = "d5a78790a1b388145424327e78f019584466d30d2d450bba832c0128aa3cd274"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {14 80 ?? ?? ?? ?? 16 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 14 80 ?? ?? ?? ?? 73 ?? ?? ?? ?? 80 ?? ?? ?? ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 14 80 ?? ?? ?? ?? 2A }

	condition:
		dotnet.is_dotnet and $s1
}
