document.addEventListener("DOMContentLoaded", function () {
    const otherCheckbox = document.getElementById('reason-other');
    const otherField = document.getElementById('other-reason-field');
    const evidenceRadios = document.querySelectorAll('input[name="evidence_choice"]');
    const photoGroup = document.getElementById('photo-group');
    const textGroup = document.getElementById('text-group');
    const coordsRadios = document.querySelectorAll('input[name="coords_choice"]');
    const coordsField = document.getElementById('coords-field');

    function toggleOther() {
        if (otherCheckbox) {
            otherField.style.display = otherCheckbox.checked ? 'block' : 'none';
            if (!otherCheckbox.checked) {
                otherField.querySelector('input').value = '';
            }
        }
    }

    function toggleEvidence() {
        const choice = document.querySelector('input[name="evidence_choice"]:checked').value;
        const photoInput = photoGroup.querySelector('input[type="file"]');
        const nameInput = textGroup.querySelector('input[name="evidence_name"]');
        const idInput = textGroup.querySelector('input[name="evidence_id"]');
        
        if (choice === 'photo') {
            photoGroup.style.display = 'block';
            textGroup.style.display = 'none';
            photoInput.required = true;
            nameInput.required = false;
            idInput.required = false;
            nameInput.value = '';
            idInput.value = '';
        } else {
            photoGroup.style.display = 'none';
            textGroup.style.display = 'block';
            photoInput.required = false;
            nameInput.required = true;
            idInput.required = true;
            photoInput.value = '';
        }
    }

    function toggleCoords() {
        const coordsYes = document.querySelector('input[name="coords_choice"]:checked');
        const coordsInput = coordsField.querySelector('input');
        
        if (coordsYes && coordsYes.value === 'yes') {
            coordsField.style.display = 'block';
        } else {
            coordsField.style.display = 'none';
            if (coordsInput) {
                coordsInput.value = '';
            }
        }
    }

    // Add event listeners
    if (otherCheckbox) {
        otherCheckbox.addEventListener('change', toggleOther);
    }
    
    evidenceRadios.forEach(r => r.addEventListener('change', toggleEvidence));
    coordsRadios.forEach(r => r.addEventListener('change', toggleCoords));

    // Initialize state
    toggleOther();
    toggleEvidence();
    toggleCoords();
});
