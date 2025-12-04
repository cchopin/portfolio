// Main JavaScript for Portfolio Interactivity

// ===========================
// Smooth Scroll for Navigation
// ===========================
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        const href = this.getAttribute('href');

        // Only prevent default for same-page anchors
        if (href !== '#' && document.querySelector(href)) {
            e.preventDefault();

            const target = document.querySelector(href);
            const navHeight = document.querySelector('.navbar')?.offsetHeight || 0;
            const targetPosition = target.offsetTop - navHeight;

            window.scrollTo({
                top: targetPosition,
                behavior: 'smooth'
            });
        }
    });
});

// ===========================
// Active Navigation Link on Scroll
// ===========================
window.addEventListener('scroll', () => {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('section[id]');

    let current = '';

    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;

        if (pageYOffset >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// ===========================
// Project Filter Functionality
// ===========================
const filterButtons = document.querySelectorAll('.filter-btn');
const projectCards = document.querySelectorAll('.project-card');

if (filterButtons.length > 0 && projectCards.length > 0) {
    filterButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons
            filterButtons.forEach(btn => btn.classList.remove('active'));
            // Add active class to clicked button
            button.classList.add('active');

            const filterValue = button.getAttribute('data-filter');

            projectCards.forEach(card => {
                if (filterValue === 'all') {
                    card.style.display = 'flex';
                    card.classList.add('fade-in');
                } else {
                    const categories = card.getAttribute('data-category').split(' ');

                    if (categories.includes(filterValue)) {
                        card.style.display = 'flex';
                        card.classList.add('fade-in');
                    } else {
                        card.style.display = 'none';
                        card.classList.remove('fade-in');
                    }
                }
            });
        });
    });
}

// ===========================
// Fade-in Animation on Scroll
// ===========================
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('fade-in');
        }
    });
}, observerOptions);

// Observe all project cards, skill cards, etc.
document.querySelectorAll('.project-card, .skill-card, .expertise-item, .stat-card').forEach(el => {
    observer.observe(el);
});

// ===========================
// Progress Bar Animation
// ===========================
const progressBars = document.querySelectorAll('.progress-fill, .level-bar');

const progressObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const bar = entry.target;
            const width = bar.style.width || bar.getAttribute('style').match(/width:\s*(\d+%)/)?.[1] || '0%';

            // Reset width to 0 then animate
            bar.style.width = '0%';
            setTimeout(() => {
                bar.style.width = width;
            }, 100);

            // Unobserve after animation
            progressObserver.unobserve(bar);
        }
    });
}, observerOptions);

progressBars.forEach(bar => {
    progressObserver.observe(bar);
});

// ===========================
// Mobile Menu Toggle (if needed)
// ===========================
const createMobileMenu = () => {
    const nav = document.querySelector('.nav-menu');
    const navContainer = document.querySelector('.nav-container');

    if (window.innerWidth <= 768 && !document.querySelector('.mobile-toggle')) {
        // Create mobile toggle button
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'mobile-toggle';
        toggleBtn.innerHTML = '<i class="fas fa-bars"></i>';
        toggleBtn.style.cssText = `
            background: none;
            border: none;
            color: var(--accent);
            font-size: 1.5rem;
            cursor: pointer;
            display: none;
        `;

        // Insert before nav menu
        navContainer.insertBefore(toggleBtn, nav);

        // Toggle menu on click
        toggleBtn.addEventListener('click', () => {
            nav.classList.toggle('mobile-active');
        });

        // Show toggle button on mobile
        if (window.innerWidth <= 768) {
            toggleBtn.style.display = 'block';
            nav.style.cssText = `
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: var(--surface);
                flex-direction: column;
                padding: 1rem;
                transform: translateY(-100%);
                opacity: 0;
                pointer-events: none;
                transition: all 0.3s ease;
            `;
        }
    }
};

// ===========================
// Stats Counter Animation
// ===========================
const animateCounter = (element, target, duration = 2000) => {
    let current = 0;
    const increment = target / (duration / 16); // 60fps

    const updateCounter = () => {
        current += increment;
        if (current < target) {
            element.textContent = Math.floor(current);
            requestAnimationFrame(updateCounter);
        } else {
            element.textContent = target;
        }
    };

    updateCounter();
};

const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const statNumber = entry.target.querySelector('.stat-number');
            if (statNumber && !statNumber.classList.contains('animated')) {
                const text = statNumber.textContent;
                const number = parseInt(text.match(/\d+/)?.[0] || 0);

                if (number > 0) {
                    statNumber.classList.add('animated');
                    animateCounter(statNumber, number);
                }
            }
        }
    });
}, observerOptions);

document.querySelectorAll('.stat-card').forEach(card => {
    statsObserver.observe(card);
});

// ===========================
// Initialize on Load
// ===========================
document.addEventListener('DOMContentLoaded', () => {
    // Add fade-in class to initially visible elements
    document.querySelectorAll('.card, .section').forEach(el => {
        el.classList.add('fade-in');
    });

    // Log portfolio load (for debugging)
    console.log('%c🛡️ Cybersecurity Portfolio Loaded', 'color: #00f0ff; font-size: 16px; font-weight: bold;');
    console.log('%cBuilt with ❤️ and code by Clémence Chopin', 'color: #888; font-size: 12px;');
});

// ===========================
// Easter Egg: Konami Code
// ===========================
let konamiCode = [];
const konamiSequence = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'b', 'a'];

document.addEventListener('keydown', (e) => {
    konamiCode.push(e.key);
    konamiCode = konamiCode.slice(-10);

    if (konamiCode.join('') === konamiSequence.join('')) {
        document.body.style.animation = 'rainbow 2s linear infinite';
        setTimeout(() => {
            document.body.style.animation = '';
        }, 5000);

        console.log('%c🎮 Konami Code Activated!', 'color: #ff00ff; font-size: 20px; font-weight: bold;');
    }
});

// Rainbow animation for easter egg
const style = document.createElement('style');
style.textContent = `
    @keyframes rainbow {
        0% { filter: hue-rotate(0deg); }
        100% { filter: hue-rotate(360deg); }
    }
`;
document.head.appendChild(style);
