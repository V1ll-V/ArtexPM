package evidence

import "golang.org/x/sys/windows"

// The staged file has already been flushed and closed. Directory File.Sync
// fails on Windows; publish the file using the native write-through move.
func installBodyFile(from, to string) error {
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
