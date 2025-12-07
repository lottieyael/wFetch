const translations = {
  en: {
    app: {
      title: "wFetch",
      subtitle: "System Overview",
      analyzeButton: "Analyze with AI",
      cooldown: "Cooldown: {{seconds}}s",
      analyzing: "Analyzing... {{percent}}%",
    },
    settings: {
      title: "Settings",
      subtitle: "Peek under the hood",
      backButton: "← Back to overview",
      version: "Version",
      theme: "Theme",
      language: "Language",
      languageHelp: "Choose language for UI and AI responses",
    },
    cards: {
      os: "Operating System",
      processor: "Processor",
      memory: "Memory",
      system: "System",
      graphics: "Graphics",
      storage: "Storage",
      network: "Network",
    },
    labels: {
      model: "Model",
      architecture: "Architecture",
      cores: "Cores",
      hostname: "Hostname",
      user: "User",
      gpu: "GPU",
      vram: "VRAM",
      noGpus: "No GPUs detected",
      adapter: "Adapter",
      noAdapters: "No active adapters",
      used: "Used",
      of: "of",
      free: "Free",
    },
  },
  es: {
    app: {
      title: "wFetch",
      subtitle: "Resumen del sistema",
      analyzeButton: "Analizar con IA",
      cooldown: "Enfriamiento: {{seconds}}s",
      analyzing: "Analizando... {{percent}}%",
    },
    settings: {
      title: "Ajustes",
      subtitle: "Echa un vistazo bajo el capó",
      backButton: "← Volver a resumen",
      version: "Versión",
      theme: "Tema",
      language: "Idioma",
      languageHelp: "Elige idioma para la interfaz y respuestas de IA",
    },
    cards: {
      os: "Sistema Operativo",
      processor: "Procesador",
      memory: "Memoria",
      system: "Sistema",
      graphics: "Gráficos",
      storage: "Almacenamiento",
      network: "Red",
    },
    labels: {
      model: "Modelo",
      architecture: "Arquitectura",
      cores: "Núcleos",
      hostname: "Nombre de equipo",
      user: "Usuario",
      gpu: "GPU",
      vram: "VRAM",
      noGpus: "No se detectaron GPUs",
      adapter: "Adaptador",
      noAdapters: "Sin adaptadores activos",
      used: "Usado",
      of: "de",
      free: "Libre",
    },
  },
  fr: {
    app: {
      title: "wFetch",
      subtitle: "Aperçu du système",
      analyzeButton: "Analyser avec l'IA",
      cooldown: "Refroidissement: {{seconds}}s",
      analyzing: "Analyse en cours... {{percent}}%",
    },
    settings: {
      title: "Paramètres",
      subtitle: "Jeter un coup d'œil sous le capot",
      backButton: "← Retour à l'aperçu",
      version: "Version",
      theme: "Thème",
      language: "Langue",
      languageHelp: "Choisir la langue pour l'interface et les réponses de l'IA",
    },
    cards: {
      os: "Système d'exploitation",
      processor: "Processeur",
      memory: "Mémoire",
      system: "Système",
      graphics: "Graphiques",
      storage: "Stockage",
      network: "Réseau",
    },
    labels: {
      model: "Modèle",
      architecture: "Architecture",
      cores: "Cœurs",
      hostname: "Nom d'hôte",
      user: "Utilisateur",
      gpu: "GPU",
      vram: "VRAM",
      noGpus: "Aucun GPU détecté",
      adapter: "Adaptateur",
      noAdapters: "Pas d'adaptateurs actifs",
      used: "Utilisé",
      of: "sur",
      free: "Libre",
    },
  },
  hu: {
    app: {
      title: "wFetch",
      subtitle: "Rendszeranalízis",
      analyzeButton: "Elemzés AI-al",
      cooldown: "Várakozási idő: {{seconds}}s",
      analyzing: "Elemzés... {{percent}}%",
    },
    settings: {
      title: "Beállítások",
      subtitle: "Alakítsd az appot úgy, ahogy tetszik",
      backButton: "← Vissza az áttekintéshez",
      application: "Alkalmazás",
      version: "Verzió",
      theme: "Téma",
      language: "Nyelv",
      languageHelp: "Válassz nyelvet a felhasználói felülethez és MI válaszokhoz",
    },
    cards: {
      os: "Operációs Rendszer",
      processor: "Processzor",
      memory: "Memória",
      system: "Rendszer",
      graphics: "Grafika",
      storage: "Tárterület",
      network: "Hálózat",
      version: "Verzió",
    },
    labels: {
      model: "Modell",
      architecture: "Architektúra",
      cores: "Magok",
      hostname: "Számítógép neve",
      user: "Felhasználó",
      gpu: "GPU",
      vram: "VRAM",
      noGpus: "Nincs GPU detektálva",
      adapter: "Adapter",
      noAdapters: "Nincs aktív adapter",
      used: "Használva",
      of: "Összesen",
      free: "Szabad",
    },
  },
  zh: {
    app: {
      title: "wFetch",
      subtitle: "系统概览",
      analyzeButton: "使用 AI 分析",
      cooldown: "冷却: {{seconds}}s",
      analyzing: "正在分析... {{percent}}%",
    },
    settings: {
      title: "设置",
      subtitle: "看看引擎盖下面",
      backButton: "← 返回概览",
      version: "版本",
      theme: "主题",
      language: "语言",
      languageHelp: "为 UI 和 AI 响应选择语言",
    },
    cards: {
      os: "操作系统",
      processor: "处理器",
      memory: "内存",
      system: "系统",
      graphics: "图形",
      storage: "存储",
      network: "网络",
    },
    labels: {
      model: "型号",
      architecture: "架构",
      cores: "核心",
      hostname: "主机名",
      user: "用户",
      gpu: "GPU",
      vram: "VRAM",
      noGpus: "未检测到 GPU",
      adapter: "适配器",
      noAdapters: "无活动适配器",
      used: "已用",
      of: "共",
      free: "可用",
    },
  },
};

export const t = (key, lang = "en", params = {}) => {
  const keys = key.split(".");
  let value = translations[lang];

  for (const k of keys) {
    value = value?.[k];
  }

  if (!value) {
    value = translations["en"];
    for (const k of keys) {
      value = value?.[k];
    }
  }

  if (typeof value === "string" && params) {
    return value.replace(/\{\{(\w+)\}\}/g, (match, paramKey) => params[paramKey] ?? match);
  }

  return value || key;
};

export default translations;