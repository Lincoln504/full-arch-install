#!/bin/bash
# wallpaper.sh v10.4 (User provided)
# Fetches a random wallpaper from Unsplash, sets it, and generates a colorscheme with pywal.

# --- Configuration ---
# API Key will be set by Ansible playbook based on user prompt.
ACCESS_KEY="YOUR_UNSPLASH_API_KEY" # Ansible replaces this

# Wallpaper directory (within user's home)
WALLPAPER_DIR="$HOME/Pictures/Wallpapers" # Changed to subfolder for organization
WALLPAPER_FILE="$WALLPAPER_DIR/current_unsplash_wallpaper.jpg"

# Unsplash query parameters
KEYWORDS="nature,minimal,landscape,abstract,dark" # Customize keywords
# RESOLUTION="2560x1440" # Removed, let Unsplash decide best based on orientation
ORIENTATION="landscape"

# --- Helper Functions ---
check_command() {
  command -v "$1" >/dev/null 2>&1 || { echo >&2 "Error: Command '$1' not found. Please install it."; exit 1; }
}

# --- Dependency Checks ---
check_command curl
check_command jq
check_command swaymsg
check_command wal # Check for pywal

# --- Main Script ---
echo "Running wallpaper script..."

# Ensure wallpaper directory exists
mkdir -p "$WALLPAPER_DIR"

# Check if API key is set
if [ "$ACCESS_KEY" = "YOUR_UNSPLASH_API_KEY" ] || [ -z "$ACCESS_KEY" ]; then
    echo "Error: Unsplash API Key (ACCESS_KEY) is not set in the script ($0)." >&2
    echo "Please provide it via Ansible prompt or edit the script directly." >&2
    exit 1 # Exit if key is mandatory now
fi

# Fetch random image URL from Unsplash API
echo "Fetching image URL from Unsplash..."
API_URL="https://api.unsplash.com/photos/random"
fetch_image_url() {
    local response
    # Construct curl command parts
    local curl_cmd=("curl" "--connect-timeout" "5" "--max-time" "10" "-s" "-G" "$API_URL")
    # Only add client_id if ACCESS_KEY is valid
    if [ "$ACCESS_KEY" != "YOUR_UNSPLASH_API_KEY" ] && [ -n "$ACCESS_KEY" ]; then
        curl_cmd+=("--data-urlencode" "client_id=$ACCESS_KEY")
    fi
    if [ -n "$KEYWORDS" ]; then
        curl_cmd+=("--data-urlencode" "query=$KEYWORDS")
    fi
    curl_cmd+=("--data-urlencode" "orientation=$ORIENTATION")
    # Removed resolution parameter: --data-urlencode "w=$RESOLUTION" --data-urlencode "h=$RESOLUTION"
    curl_cmd+=("-H" "Accept-Version: v1") # Specify API version

    # Execute curl command
    echo "DEBUG: Running: ${curl_cmd[*]}" >&2
    response=$("${curl_cmd[@]}")
    local curl_ec=$?
    if [ $curl_ec -ne 0 ]; then
        echo "Error: curl command failed with exit code $curl_ec" >&2
        return 1
    fi


    # Check for errors in response
    if echo "$response" | jq -e '.errors' > /dev/null; then
        echo "Error fetching image from Unsplash:" >&2
        echo "$response" | jq '.errors' >&2
        return 1
    fi

    # Extract the full URL (prefer 'full' for quality)
    local url
    url=$(echo "$response" | jq -r '.urls.full // .urls.raw // .urls.regular') # Fallback URLs

    if [ -z "$url" ] || [ "$url" = "null" ]; then
        echo "Error: Could not extract image URL from Unsplash response." >&2
        echo "Response: $response" >&2
        return 1
    fi

    echo "$url"
    return 0
}

IMAGE_URL=$(fetch_image_url)
if [ $? -ne 0 ]; then
    echo "Failed to get image URL. Exiting."
    exit 1
fi

echo "Image URL: $IMAGE_URL"

# Download and set wallpaper
echo "Downloading wallpaper to $WALLPAPER_FILE..."
if curl --connect-timeout 5 --max-time 60 -L -f -o "$WALLPAPER_FILE" "$IMAGE_URL"; then
    echo "Download complete."
    echo "Setting wallpaper using swaymsg..."
    if swaymsg output "*" bg "$WALLPAPER_FILE" fill; then
        echo "Wallpaper set via swaymsg."
    else
        echo "Error setting wallpaper with swaymsg. Is sway running?" >&2
        # Fallback attempt using swaybg directly (less ideal for dynamic changes)
        # pkill swaybg || true
        # swaybg -i "$WALLPAPER_FILE" -m fill &
    fi
else
    echo "Error downloading wallpaper from $IMAGE_URL." >&2
    # Clean up potentially incomplete file
    rm -f "$WALLPAPER_FILE"
    exit 1
fi


# Generate colorscheme using pywal
echo "Generating colorscheme with pywal..."
if wal -n -q -s -t -i "$WALLPAPER_FILE"; then # -n skip term colors, -q quiet, -s skip bg set, -t fix tty vim
   echo "Pywal colorscheme generated."
else
   echo "Error generating colorscheme with pywal." >&2
fi

# Restart Waybar to apply new colors/modules if needed
if pgrep -x "waybar" > /dev/null; then
    echo "Reloading Waybar..."
    pkill -SIGUSR2 waybar # Send reload signal
else
    echo "Waybar not running, skipping reload."
fi

echo "Wallpaper script finished."
exit 0
