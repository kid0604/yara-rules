import "hash"

rule GandCrab_hash
{
	meta:
		description = "Detect the risk of GandCrab Rule 1"
		os = "windows"
		filetype = "executable"

	condition:
		hash.sha256(0, filesize )=="49b769536224f160b6087dc866edf6445531c6136ab76b9d5079ce622b043200" or hash.sha256(0, filesize )=="a45bd4059d804b586397f43ee95232378d519c6b8978d334e07f6047435fe926"
}
