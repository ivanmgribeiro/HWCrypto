TMP_DIRS = -bdir build_dir  -simdir build_dir  -info-dir build_dir

INCLUDE_DIRS = :../libs/BlueStuff/AXI:../libs/BlueStuff/BlueBasics:../libs/BlueStuff:src_Test:src_HWCrypto:src_Boot_ROM:src_Mem_Model:+
#	    -p $(INCLUDE_DIRS) \

build_dir:
	mkdir -p build_dir

compile: build_dir
	bsc -u \
	    -elab \
	    -sim \
	    $(TMP_DIRS) \
	    $(BSC_COMPILATION_FLAGS) \
	    -p $(INCLUDE_DIRS) \
	    -g mkTest_Top \
	    src_Test/Test_Top.bsv

test: compile
	bsc -sim \
	    $(TMP_DIRS) \
	    -e mkTest_Top \
	    -o ./crypto_sim

clean:
	rm -rf ./build_dir/*
