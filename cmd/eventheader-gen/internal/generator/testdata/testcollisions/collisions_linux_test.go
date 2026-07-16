//go:build linux

package testcollisions

var TopLevelTestEventSchema int

func (*MethodTestEventWriter) Write() {}

func testHelper() {}

func (*NoncollidingTestEventWriter) ResetForTest() {}
