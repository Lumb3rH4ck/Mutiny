.PHONY: all build install run run-tui dev watch clean

BINARY := mutiny
INSTALL_DIR := /usr/local/bin
BUILD_DIR := build

all: build

build:
	go build -o $(BINARY) .
	@echo "Built ./$(BINARY)"

install: build
	sudo cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	sudo chmod 755 $(INSTALL_DIR)/$(BINARY)
	sudo mkdir -p /usr/local/share/icons/hicolor/256x256/apps
	sudo mkdir -p /usr/local/share/icons/hicolor/48x48/apps
	sudo cp $(BUILD_DIR)/icons/mutiny.png /usr/local/share/icons/hicolor/256x256/apps/mutiny.png
	sudo cp $(BUILD_DIR)/icons/mutiny-48.png /usr/local/share/icons/hicolor/48x48/apps/mutiny.png
	sudo chmod 644 /usr/local/share/icons/hicolor/*/apps/mutiny.png
	mkdir -p $(HOME)/.local/share/applications
	cp $(BUILD_DIR)/mutiny.desktop $(HOME)/.local/share/applications/
	cp $(BUILD_DIR)/mutiny-tui.desktop $(HOME)/.local/share/applications/
	sed -i "s|/usr/local/bin/mutiny|$(INSTALL_DIR)/$(BINARY)|g" $(HOME)/.local/share/applications/mutiny.desktop
	sed -i "s|/usr/local/bin/mutiny|$(INSTALL_DIR)/$(BINARY)|g" $(HOME)/.local/share/applications/mutiny-tui.desktop
	update-desktop-database $(HOME)/.local/share/applications 2>/dev/null || true
	@# Register mutiny as the default handler for .torrent files and magnet: links.
	xdg-mime default mutiny.desktop application/x-bittorrent || true
	xdg-mime default mutiny.desktop x-scheme-handler/magnet || true
	xdg-settings set default-url-scheme-handler magnet mutiny.desktop || true
	sudo gtk-update-icon-cache /usr/local/share/icons/hicolor 2>/dev/null || true
	@echo "Installed to $(INSTALL_DIR)/$(BINARY)"

run: build
	./$(BINARY) -mode server

run-tui: build
	./$(BINARY) -mode tui

dev:
	air -c .air.toml

watch:
	@echo "Watching for changes... (Ctrl+C to stop)"
	@find . -name '*.go' -o -name '*.html' -o -name '*.css' -o -name '*.js' | entr -r make run

clean:
	rm -f $(BINARY)
	@echo "Cleaned"

deps:
	go mod tidy
	@echo "Dependencies updated"

.DEFAULT_GOAL := build
