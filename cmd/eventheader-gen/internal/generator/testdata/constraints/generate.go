package constraints

//go:generate go run ../../../../ -type=LinuxEvent -output=linux_eventheader.go
//go:generate go run ../../../../ -tags=custom -type=CustomEvent -output=custom_eventheader.go
//go:generate go run ../../../../ -type=FilenameLinuxEvent -output=filename_linux_eventheader.go
//go:generate go run ../../../../ -type=FilenameLinuxAMD64Event -output=filename_linux_amd64_eventheader.go
//go:generate go run ../../../../ -type=FilenameAMD64Event -output=filename_amd64_eventheader.go
//go:generate go run ../../../../ -tags=custom -type=CombinedLinuxAMD64Event -output=combined_linux_amd64_eventheader.go
