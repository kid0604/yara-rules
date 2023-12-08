import "hash"

private rule xmrig_5_9_0
{
	meta:
		description = "xmrig.elf"
		os = "linux"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="d351de486d4bb4e80316e1524682c602"
}
