// Matrix Rain Effect
document.addEventListener('DOMContentLoaded', function() {
const canvas = document.getElementById('matrix-canvas');
if (!canvas) return;
const ctx = canvas.getContext('2d');

// Set canvas size
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

// Characters for the matrix effect - Binary, Hex, and special characters
const chars = '01'.split('');

// Font size and column calculation
const fontSize = 14;
const columns = canvas.width / fontSize;

// Array to hold the y-position of each drop
const drops = [];
for (let i = 0; i < columns; i++) {
    drops[i] = Math.floor(Math.random() * -100);
}

// Function to draw the matrix effect
function drawMatrix() {
    // Semi-transparent black to create fade effect
    ctx.fillStyle = 'rgba(15, 15, 17, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Set text color and font
    ctx.fillStyle = 'rgba(0, 240, 255, 0.8)';
    ctx.font = `${fontSize}px monospace`;

    // Loop through drops
    for (let i = 0; i < drops.length; i++) {
        // Random character from the array
        const text = chars[Math.floor(Math.random() * chars.length)];

        // Draw the character
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        // Reset drop to top randomly after it crosses the screen
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }

        // Increment y position
        drops[i]++;
    }
}

// Animation interval
setInterval(drawMatrix, 50);

// Resize canvas on window resize
window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    // Recalculate columns
    const newColumns = canvas.width / fontSize;
    drops.length = 0;
    for (let i = 0; i < newColumns; i++) {
        drops[i] = Math.floor(Math.random() * -100);
    }
});

}); // End DOMContentLoaded
