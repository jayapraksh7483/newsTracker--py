function likePost(postId) {
    fetch('/like/' + postId, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    })
    .then(async (response) => {
        if (response.redirected) {
            window.location.href = response.url;
            return null;
        }
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            return response.json();
        }
        if (!response.ok) {
            throw new Error('Request failed');
        }
        return { success: false };
    })
    .then((data) => {
        if (!data) return;
        if (data.success) {
            // Update the like button and count
            const likeBtn = document.querySelector(`[data-post-id="${postId}"]`);
            if (likeBtn) {
                const likeIcon = likeBtn.querySelector('.like-icon');
                const likeCount = likeBtn.querySelector('.like-count');
                
                if (data.alreadyLiked) {
                    // User just liked, show as liked
                    likeBtn.classList.add('liked');
                    likeIcon.textContent = '❤️';
                } else {
                    // User just unliked, show as not liked
                    likeBtn.classList.remove('liked');
                    likeIcon.textContent = '🤍';
                }
                
                // Update count
                likeCount.textContent = data.likes;
            }
        } else {
            alert('Please login to like posts.');
        }
    })
    .catch(() => {
        alert('Unable to like right now. Please try again.');
    });
}

// ---------- Modal functionality ----------
function showDescription(description) {
    const modal = document.getElementById('descriptionModal');
    const modalDescription = document.getElementById('modalDescription');

    if (modal && modalDescription) {
        modalDescription.textContent = description;
        modal.style.display = 'flex';  // assumes CSS .modal { display:none; justify-content:center; align-items:center; }
    }
}

function closeModal() {
    const modal = document.getElementById('descriptionModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const modal = document.getElementById('descriptionModal');
    if (modal) {
        const closeBtn = modal.querySelector('.modal-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', closeModal);
        }

        // Close modal when clicking outside
        modal.addEventListener('click', function (e) {
            if (e.target === modal) {
                closeModal();
            }
        });

        // Close modal with Escape key
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && modal.style.display === 'flex') {
                closeModal();
            }
        });
    }
});
