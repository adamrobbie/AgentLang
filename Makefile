# Makefile for AgentLang WASM Modules

# Target directory for WASM
WASM_OUT_DIR = wasm_modules
# Rust target for WASM
WASM_TARGET = wasm32-unknown-unknown

.PHONY: all clean build-wasm check-tools

all: check-tools build-wasm

check-tools:
	@echo "Checking for WASM target..."
	@rustup target list | grep $(WASM_TARGET) | grep installed || rustup target add $(WASM_TARGET)

build-wasm:
	@echo "Building WASM modules..."
	@mkdir -p $(WASM_OUT_DIR)
	@# Assuming you have a rust project or workspace members for WASM tools:
	@# cd path/to/wasm_tool && cargo build --target $(WASM_TARGET) --release
	@# cp path/to/wasm_tool/target/$(WASM_TARGET)/release/*.wasm $(WASM_OUT_DIR)/
	@echo "WASM build pipeline configured. Add your rust/c to wasm compilation commands here."

clean:
	@echo "Cleaning WASM output..."
	@rm -f $(WASM_OUT_DIR)/*.wasm
