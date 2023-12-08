import "hash"

rule Magniber_hash
{
	meta:
		description = "Detect the risk of Magniber Rule 1"
		os = "windows"
		filetype = "executable"

	condition:
		hash.sha256(0, filesize )=="a09b48239e7aba75085e2217e13da0eb1cb8f01a2e4e08632769097e0c412b9f"
}
