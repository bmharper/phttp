
ifdef WINDOWS
	CXX := cl.exe /FS /Zi /EHsc /O2 /nologo
	CXX_EXE_OUT := /Fe
	CXX_OBJ_OUT := /Fo
	SERVER := server.exe
	UNIT := unit.exe
	OBJ := .obj
	EXE := .exe
else
	CXX := clang++ -std=c++11 -ggdb -lpthread
	CXX_EXE_OUT := -o  
	CXX_OBJ_OUT := -o  
	SERVER := server
	UNIT := unit
	OBJ := .o
	EXE := 
endif

# target directory
OUT := build

# With this, you can do "make print-VARIABLE" to dump the value of that variable
print-% : ; @echo $* = $($*)

SERVER_CPP := tests/server.cpp phttp.cpp
SERVER_C := sha1.c http11/http11_parser.c

DEMO_CPP := demo.cpp phttp.cpp
DEMO_C := sha1.c http11/http11_parser.c

UNIT_CPP := tests/unit.cpp phttp.cpp
UNIT_C := sha1.c http11/http11_parser.c

DEMO_OBJ = $(patsubst %.cpp, $(OUT)/%$(OBJ), $(DEMO_CPP)) $(patsubst %.c, $(OUT)/%$(OBJ), $(DEMO_C))
SERVER_OBJ = $(patsubst %.cpp, $(OUT)/%$(OBJ), $(SERVER_CPP)) $(patsubst %.c, $(OUT)/%$(OBJ), $(SERVER_C))
UNIT_OBJ = $(patsubst %.cpp, $(OUT)/%$(OBJ), $(UNIT_CPP)) $(patsubst %.c, $(OUT)/%$(OBJ), $(UNIT_C))

$(OUT)/%$(OBJ): %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXX_OBJ_OUT)$@ -c $<

$(OUT)/%$(OBJ): %.c
	@mkdir -p $(@D)
	$(CXX) $(CXX_OBJ_OUT)$@ -c $<

$(OUT)/demo$(EXE): $(DEMO_OBJ)
	$(CXX) $(CXX_EXE_OUT)$@ $(DEMO_OBJ)

$(OUT)/server$(EXE): $(SERVER_OBJ)
	$(CXX) $(CXX_EXE_OUT)$@ $(SERVER_OBJ)

$(OUT)/unit$(EXE): $(UNIT_OBJ)
	$(CXX) $(CXX_EXE_OUT)$@ $(UNIT_OBJ)