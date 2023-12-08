import "hash"
import "pe"

rule Sodinokibi_hash
{
	meta:
		description = "Detect the risk of Sodinokibi Rule 13"
		os = "windows"
		filetype = "executable"

	condition:
		hash.sha256(0, filesize )=="67c4d6f5844c2549e75b876cb32df8b22d2eae5611feeb37f9a2097d67cc623e"
}
