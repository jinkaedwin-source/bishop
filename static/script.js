const menuButton = document.querySelector(".menu-toggle");
const nav = document.querySelector(".nav");

if (menuButton && nav) {
  menuButton.addEventListener("click", () => {
    nav.classList.toggle("open");
  });
}

const observer = new IntersectionObserver(
  entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) entry.target.classList.add("visible");
    });
  },
  { threshold: 0.16 }
);

document.querySelectorAll(".reveal").forEach(element => observer.observe(element));

const translations = {
  en: {
    home_welcome: "Welcome to LIGHT INTERNATIONAL MINISTRY",
    home_title: "Shining the light of Christ to nations, families, and generations.",
    home_verse: "\"You are the light of the world. A city set on a hill cannot be hidden.\"",
    watch_sermons: "Watch Sermons",
    submit_prayer: "Submit Prayer Request",
    mission_label: "Mission",
    mission_title: "To lead people into a living relationship with Jesus Christ.",
    mission_text: "We proclaim the gospel, teach the Word, nurture believers, strengthen families, and serve communities with compassion and truth.",
    vision_label: "Vision",
    vision_title: "A Christ-centered church carrying light to the world.",
    vision_text: "Our vision is to raise mature disciples who worship deeply, pray faithfully, and live as witnesses of God's kingdom in every sphere."
  },
  fr: {
    home_welcome: "Bienvenue a LIGHT INTERNATIONAL MINISTRY",
    home_title: "Faire briller la lumiere de Christ pour les nations, les familles et les generations.",
    home_verse: "\"Vous etes la lumiere du monde. Une ville situee sur une montagne ne peut etre cachee.\"",
    watch_sermons: "Voir les sermons",
    submit_prayer: "Envoyer une requete de priere",
    mission_label: "Mission",
    mission_title: "Conduire les personnes dans une relation vivante avec Jesus-Christ.",
    mission_text: "Nous proclamons l'Evangile, enseignons la Parole, fortifions les croyants, soutenons les familles et servons les communautes avec compassion et verite.",
    vision_label: "Vision",
    vision_title: "Une eglise centree sur Christ qui porte la lumiere au monde.",
    vision_text: "Notre vision est de former des disciples matures qui adorent profondement, prient fidelement et vivent comme temoins du royaume de Dieu."
  },
  es: {
    home_welcome: "Bienvenido a LIGHT INTERNATIONAL MINISTRY",
    home_title: "Brillando la luz de Cristo a naciones, familias y generaciones.",
    home_verse: "\"Ustedes son la luz del mundo. Una ciudad sobre un monte no se puede esconder.\"",
    watch_sermons: "Ver sermones",
    submit_prayer: "Enviar peticion de oracion",
    mission_label: "Mision",
    mission_title: "Guiar a las personas a una relacion viva con Jesucristo.",
    mission_text: "Proclamamos el evangelio, ensenamos la Palabra, fortalecemos creyentes, apoyamos familias y servimos comunidades con compasion y verdad.",
    vision_label: "Vision",
    vision_title: "Una iglesia centrada en Cristo que lleva luz al mundo.",
    vision_text: "Nuestra vision es formar discipulos maduros que adoren profundamente, oren fielmente y vivan como testigos del reino de Dios."
  }
};

const languageSelect = document.querySelector("#language-select");

function applyLanguage(language) {
  const selected = translations[language] || translations.en;
  document.querySelectorAll("[data-i18n]").forEach(element => {
    const key = element.getAttribute("data-i18n");
    if (selected[key]) element.textContent = selected[key];
  });
  document.documentElement.lang = language;
  localStorage.setItem("siteLanguage", language);
}

if (languageSelect) {
  const savedLanguage = localStorage.getItem("siteLanguage") || "en";
  languageSelect.value = savedLanguage;
  applyLanguage(savedLanguage);
  languageSelect.addEventListener("change", event => applyLanguage(event.target.value));
}

const chatToggle = document.querySelector(".ai-chat-toggle");
const chatPanel = document.querySelector(".ai-chat-panel");
const chatClose = document.querySelector(".ai-chat-close");
const chatForm = document.querySelector(".ai-chat-form");
const chatInput = document.querySelector("#ai-chat-input");
const chatBody = document.querySelector("#ai-chat-body");

function addChatMessage(text, sender) {
  const message = document.createElement("div");
  message.className = `ai-message ${sender}`;
  message.textContent = text;
  chatBody.appendChild(message);
  chatBody.scrollTop = chatBody.scrollHeight;
}

if (chatToggle && chatPanel) {
  chatToggle.addEventListener("click", () => {
    const isHidden = chatPanel.hasAttribute("hidden");
    chatPanel.toggleAttribute("hidden", !isHidden);
    chatToggle.setAttribute("aria-expanded", String(isHidden));
    if (isHidden && chatInput) chatInput.focus();
  });
}

if (chatClose && chatPanel && chatToggle) {
  chatClose.addEventListener("click", () => {
    chatPanel.setAttribute("hidden", "");
    chatToggle.setAttribute("aria-expanded", "false");
  });
}

if (chatForm && chatInput && chatBody) {
  chatForm.addEventListener("submit", async event => {
    event.preventDefault();
    const text = chatInput.value.trim();
    if (!text) return;
    addChatMessage(text, "visitor");
    chatInput.value = "";
    try {
      const response = await fetch("/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
      });
      const data = await response.json();
      addChatMessage(data.reply || "BISHOP is available to help with prayer and ministry guidance.", "bishop");
    } catch (error) {
      addChatMessage("BISHOP is temporarily unavailable. Please try again or use the Contact page.", "bishop");
    }
  });
}
