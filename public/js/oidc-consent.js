// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// This script adds the upstream_parameters.prompt=consent parameter to Google OAuth login
// This forces Google to display the consent screen and issue a refresh token
document.addEventListener("DOMContentLoaded", function () {
  // Find all forms on the page
  const forms = document.querySelectorAll("form")

  forms.forEach((form) => {
    // Check if this is a Google OAuth login form
    const googleButton = form.querySelector('button[value="google"]')
    if (googleButton) {
      console.log("Found Google OAuth form")

      // Add submit event listener
      form.addEventListener("submit", function (event) {
        // Check if we already added the parameter
        if (!form.querySelector('input[name="upstream_parameters.prompt"]')) {
          // Create a hidden input for the prompt=consent parameter
          const hiddenInput = document.createElement("input")
          hiddenInput.type = "hidden"
          hiddenInput.name = "upstream_parameters.prompt"
          hiddenInput.value = "consent"

          // Add it to the form before submission
          form.appendChild(hiddenInput)
          console.log("Added prompt=consent parameter")
        }
      })
    }
  })
})
