rule fopo_webshell
{
	meta:
		description = "Detects the presence of the FOPO webshell in files"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ = "DNEcHdQbWtXU3dSMDA1VmZ1c29WUVFXdUhPT0xYb0k3ZDJyWmFVZlF5Y0ZEeHV4K2FnVmY0OUtjbzhnc0"
		$ = "U3hkTVVibSt2MTgyRjY0VmZlQWo3d1VlaFJVNVNnSGZUVUhKZXdEbGxJUTlXWWlqWSt0cEtacUZOSXF4c"
		$ = "rb2JHaTJVdURMNlhQZ1ZlTGVjVnFobVdnMk5nbDlvbEdBQVZKRzJ1WmZUSjdVOWNwWURZYlZ0L1BtNCt"

	condition:
		any of them
}
