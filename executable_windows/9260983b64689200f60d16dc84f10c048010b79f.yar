import "hash"

rule globeimposter_hash
{
	meta:
		description = "Detect the risk of globeimposter Rule 4"
		os = "windows"
		filetype = "executable"

	condition:
		hash.sha256(0, filesize )=="70866cee3b129918e2ace1870e66801bc25a18efd6a8c0234a63fccaee179b68" or hash.sha256(0, filesize )=="8b6993a935c33bbc028b2c72d7b2e769ff2cd5ad35331bc4d2dcce67a0c81569"
}
