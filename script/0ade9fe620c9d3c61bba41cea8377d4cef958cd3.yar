rule HKTL_NFS_Fuse_NFS
{
	meta:
		description = "Detects the nfs-security-tooling fuse_nfs by HvS Consulting"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Moritz Oettle"
		date = "2024-10-22"
		score = 75
		reference = "https://github.com/hvs-consulting/nfs-security-tooling"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "NFS3ConnectionFactory" fullword ascii
		$s2 = "fuse_to_nfs_timestamp" fullword ascii
		$s3 = "--manual-fh" fullword ascii
		$s4 = "--fake-uid-allow-root" fullword ascii
		$s5 = "nfs.rpc.credential" fullword ascii
		$s6 = "nfs.readlink" fullword ascii
		$s7 = "pyfuse3.EntryAttributes" fullword ascii
		$s8 = "Make nested exports on NetApp servers work" fullword ascii
		$s9 = "add_mutually_exclusive_group" fullword ascii

	condition:
		4 of them
}
