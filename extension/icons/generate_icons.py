"""
Script to generate PNG icons for the browser extension.
Requires Pillow: pip install Pillow
"""

try:
    from PIL import Image, ImageDraw
    import os
    
    def create_icon(size):
        """Create a simple lock icon with gradient-like colors"""
        # Create image with gradient background
        img = Image.new('RGB', (size, size), color='white')
        draw = ImageDraw.Draw(img)
        
        # Draw gradient background (simplified)
        for y in range(size):
            # Gradient from #667eea to #764ba2
            r = int(102 + (118 - 102) * y / size)
            g = int(126 + (75 - 126) * y / size)
            b = int(234 + (162 - 234) * y / size)
            draw.rectangle([(0, y), (size, y+1)], fill=(r, g, b))
        
        # Calculate lock dimensions based on icon size
        scale = size / 128
        
        # Lock body
        lock_width = int(48 * scale)
        lock_height = int(40 * scale)
        lock_x = (size - lock_width) // 2
        lock_y = int(56 * scale)
        corner_radius = int(4 * scale)
        
        # Draw lock body
        draw.rounded_rectangle(
            [(lock_x, lock_y), (lock_x + lock_width, lock_y + lock_height)],
            radius=corner_radius,
            outline='white',
            width=max(2, int(6 * scale))
        )
        
        # Lock shackle
        shackle_radius = int(10 * scale)
        shackle_x = size // 2
        shackle_y = int(48 * scale)
        shackle_width = max(2, int(6 * scale))
        
        draw.arc(
            [(shackle_x - shackle_radius, shackle_y - shackle_radius),
             (shackle_x + shackle_radius, shackle_y + shackle_radius)],
            start=180, end=0,
            fill='white',
            width=shackle_width
        )
        
        # Keyhole
        keyhole_radius = int(6 * scale)
        keyhole_x = size // 2
        keyhole_y = int(76 * scale)
        
        draw.ellipse(
            [(keyhole_x - keyhole_radius, keyhole_y - keyhole_radius),
             (keyhole_x + keyhole_radius, keyhole_y + keyhole_radius)],
            fill='white'
        )
        
        return img
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icons_dir = script_dir
    
    # Create icons
    sizes = [16, 48, 128]
    for size in sizes:
        print(f"Generating {size}x{size} icon...")
        icon = create_icon(size)
        icon.save(os.path.join(icons_dir, f'icon{size}.png'))
        print(f"✓ Saved icon{size}.png")
    
    print("\n✓ All icons generated successfully!")
    print("You can now load the extension in your browser.")

except ImportError:
    print("Error: Pillow library not found.")
    print("Please install it using: pip install Pillow")
    print("\nAlternatively, you can:")
    print("1. Create icons manually using any image editor")
    print("2. Save them as icon16.png, icon48.png, and icon128.png in the icons folder")
    print("3. Or use online tools to convert the icon.svg to PNG files")
