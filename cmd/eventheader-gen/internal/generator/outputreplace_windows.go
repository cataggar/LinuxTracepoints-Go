//go:build windows

package generator

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const replaceFileWriteThrough = 0x00000001

var replaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func replaceExistingOutput(
	tempName string,
	initial outputState,
	hooks *replacementHooks,
) (preserveTemp bool, err error) {
	staged, err := readOutputState(tempName)
	if err != nil {
		return false, err
	}
	if hooks != nil && hooks.beforeCommit != nil {
		hooks.beforeCommit()
	}

	targetName, err := windows.UTF16PtrFromString(initial.path)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(
		targetName,
		windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return false, concurrentModificationError(initial.path)
	}
	target := os.NewFile(uintptr(handle), initial.path)
	defer target.Close()

	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		allLockBytes,
		allLockBytes,
		overlapped,
	); err != nil {
		return false, fmt.Errorf("lock existing output %q: %w", initial.path, err)
	}
	defer windows.UnlockFileEx(handle, 0, allLockBytes, allLockBytes, overlapped)

	held, err := readOpenOutputState(target, initial.path)
	if err != nil || !initial.exists || !bytes.Equal(initial.data, held.data) {
		return false, concurrentModificationError(initial.path)
	}
	samePath, err := pathRefersToHandle(initial.path, handle)
	if err != nil || !samePath {
		return false, concurrentModificationError(initial.path)
	}

	backupName := tempName + ".previous"
	if err := windowsReplaceFile(initial.path, tempName, backupName); err != nil {
		return false, fmt.Errorf("atomically replace generated output %q: %w", initial.path, err)
	}
	if hooks != nil && hooks.afterCommit != nil {
		hooks.afterCommit()
	}
	previous, err := readOutputState(backupName)
	if err != nil {
		return false, fmt.Errorf("inspect replaced prior output %q (preserved at %q): %w",
			initial.path, backupName, err)
	}
	if sameOutputState(initial, previous) {
		if err := removeVerifiedOutputState(backupName, previous); err != nil {
			return false, fmt.Errorf("remove prior output backup %q: %w", backupName, err)
		}
		return false, nil
	}

	current, err := readOutputState(initial.path)
	if err != nil {
		return false, fmt.Errorf("%w; prior output preserved at %q: %v",
			concurrentModificationError(initial.path), backupName, err)
	}
	if !sameOutputState(staged, current) {
		if err := removeVerifiedOutputState(backupName, previous); err != nil {
			return false, fmt.Errorf("%w; prior output preserved at %q: %v",
				concurrentModificationError(initial.path), backupName, err)
		}
		return false, concurrentModificationError(initial.path)
	}
	if err := rollbackReplaceFile(
		tempName,
		initial.path,
		backupName,
		staged,
		previous,
		replaceFileRollbackOps{
			replace:        windowsReplaceFile,
			read:           readOutputState,
			same:           sameOutputState,
			removeVerified: removeVerifiedOutputState,
		},
	); err != nil {
		return false, err
	}
	return false, concurrentModificationError(initial.path)
}

func removeVerifiedOutputState(path string, expected outputState) error {
	current, err := readOutputState(path)
	if err != nil {
		return err
	}
	if !sameOutputState(expected, current) {
		return fmt.Errorf("output changed; preserved at %q", path)
	}
	return os.Remove(path)
}

func pathRefersToHandle(path string, handle windows.Handle) (bool, error) {
	pathName, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	pathHandle, err := windows.CreateFile(
		pathName,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(pathHandle)

	var heldInfo, pathInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &heldInfo); err != nil {
		return false, err
	}
	if err := windows.GetFileInformationByHandle(pathHandle, &pathInfo); err != nil {
		return false, err
	}
	return heldInfo.VolumeSerialNumber == pathInfo.VolumeSerialNumber &&
		heldInfo.FileIndexHigh == pathInfo.FileIndexHigh &&
		heldInfo.FileIndexLow == pathInfo.FileIndexLow, nil
}

func readOpenOutputState(file *os.File, path string) (outputState, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return outputState{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return outputState{}, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return outputState{}, err
	}
	return outputState{path: path, exists: true, data: data, info: info}, nil
}

func windowsReplaceFile(target, replacement, backup string) error {
	targetName, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	replacementName, err := windows.UTF16PtrFromString(replacement)
	if err != nil {
		return err
	}
	backupName, err := windows.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}
	result, _, callErr := replaceFileW.Call(
		uintptr(unsafe.Pointer(targetName)),
		uintptr(unsafe.Pointer(replacementName)),
		uintptr(unsafe.Pointer(backupName)),
		replaceFileWriteThrough,
		0,
		0,
	)
	if result != 0 {
		return nil
	}
	if callErr == nil || errors.Is(callErr, windows.ERROR_SUCCESS) {
		return windows.ERROR_GEN_FAILURE
	}
	return callErr
}
