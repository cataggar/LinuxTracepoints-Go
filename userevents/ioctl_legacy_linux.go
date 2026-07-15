//go:build linux && (mips || mipsle || mips64 || mips64le || ppc64 || ppc64le)

package userevents

import "unsafe"

const (
	ioctlTypeBits = 8
	ioctlSizeBits = 13

	ioctlTypeShift = 8
	ioctlSizeShift = ioctlTypeShift + ioctlTypeBits
	ioctlDirShift  = ioctlSizeShift + ioctlSizeBits

	ioctlWrite = 4
	ioctlRead  = 2

	ioctlPointerSize = unsafe.Sizeof(uintptr(0))

	diagIOCSReg = uintptr(
		(ioctlRead|ioctlWrite)<<ioctlDirShift |
			ioctlPointerSize<<ioctlSizeShift |
			'*'<<ioctlTypeShift,
	)
	diagIOCSDel   = uintptr(ioctlWrite<<ioctlDirShift | ioctlPointerSize<<ioctlSizeShift | '*'<<ioctlTypeShift | 1)
	diagIOCSUnreg = uintptr(ioctlWrite<<ioctlDirShift | ioctlPointerSize<<ioctlSizeShift | '*'<<ioctlTypeShift | 2)

	legacyIoctlEncoding = true
)
