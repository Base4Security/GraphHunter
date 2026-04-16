import { useState, useCallback, useRef } from "react";
import { invoke, errorMessage } from "../lib/tauri";
import type {
  AiProvider,
  AiAnalysisResponse,
  AiSuggestion,
  ConversationMessage,
  LogEntry,
} from "../types";

export interface AiAnalysisState {
  analyzeAiOpen: boolean;
  analyzeAiLoading: boolean;
  analyzeAiError: string | null;
  analyzeAiQuestion: string;
  aiConversation: ConversationMessage[];
  aiLastSuggestions: AiSuggestion[];
  aiProvider: AiProvider;
  aiApiKey: string;
  aiModel: string;
  aiBaseUrl: string;
  aiSettingsOpen: boolean;
  aiChatEndRef: React.RefObject<HTMLDivElement | null>;
}

export interface AiAnalysisActions {
  setAnalyzeAiOpen: (open: boolean) => void;
  setAnalyzeAiQuestion: (q: string) => void;
  setAiProvider: (p: AiProvider) => void;
  setAiApiKey: (k: string) => void;
  setAiModel: (m: string) => void;
  setAiBaseUrl: (u: string) => void;
  setAiSettingsOpen: (open: boolean) => void;
  sendAiMessage: (message: string) => Promise<void>;
  runAnalyzeAi: () => Promise<void>;
  clearAiConversation: () => Promise<void>;
  saveAiProvider: () => Promise<void>;
  handleAiSuggestion: (suggestion: AiSuggestion) => Promise<void>;
}

export function useAiAnalysis(
  addLog: (entry: LogEntry) => void,
): AiAnalysisState & AiAnalysisActions {
  const [analyzeAiOpen, setAnalyzeAiOpen] = useState(false);
  const [analyzeAiLoading, setAnalyzeAiLoading] = useState(false);
  const [analyzeAiError, setAnalyzeAiError] = useState<string | null>(null);
  const [analyzeAiQuestion, setAnalyzeAiQuestion] = useState("");
  const [aiConversation, setAiConversation] = useState<ConversationMessage[]>([]);
  const [aiLastSuggestions, setAiLastSuggestions] = useState<AiSuggestion[]>([]);
  const [aiProvider, setAiProvider] = useState<AiProvider>("OpenAI");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [aiBaseUrl, setAiBaseUrl] = useState("");
  const [aiSettingsOpen, setAiSettingsOpen] = useState(false);
  const aiChatEndRef = useRef<HTMLDivElement | null>(null);

  const sendAiMessage = useCallback(async (message: string) => {
    const now = Math.floor(Date.now() / 1000);
    setAiConversation((prev) => [
      ...prev,
      { role: "user", content: message, timestamp: now },
    ]);
    setAiLastSuggestions([]);
    setAnalyzeAiLoading(true);
    setAnalyzeAiError(null);
    setAnalyzeAiQuestion("");
    setTimeout(() => aiChatEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
    try {
      const response = await invoke<AiAnalysisResponse>("cmd_ai_chat", {
        userMessage: message,
      });
      const nowDone = Math.floor(Date.now() / 1000);
      setAiConversation((prev) => [
        ...prev,
        { role: "assistant", content: response.text, timestamp: nowDone },
      ]);
      setAiLastSuggestions(response.suggestions || []);
      setTimeout(() => aiChatEndRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch (e) {
      setAnalyzeAiError(errorMessage(e));
    } finally {
      setAnalyzeAiLoading(false);
    }
  }, []);

  const runAnalyzeAi = useCallback(async () => {
    const message = analyzeAiQuestion.trim() || "Analyze the graph for suspicious activity.";
    sendAiMessage(message);
  }, [analyzeAiQuestion, sendAiMessage]);

  const clearAiConversation = useCallback(async () => {
    try {
      await invoke("cmd_ai_clear_conversation");
    } catch { /* ignore */ }
    setAiConversation([]);
    setAiLastSuggestions([]);
  }, []);

  const saveAiProvider = useCallback(async () => {
    try {
      const detected = await invoke<string>("cmd_ai_set_provider", {
        provider: aiProvider.toLowerCase(),
        apiKey: aiApiKey,
        model: aiModel || null,
        baseUrl: aiBaseUrl || null,
      });
      if (detected && detected !== "none") {
        setAiProvider(detected as AiProvider);
      }
      setAiSettingsOpen(false);
      addLog({ time: new Date().toLocaleTimeString(), message: `AI provider set to ${detected || aiProvider}`, level: "success" });
    } catch (e) {
      setAnalyzeAiError(errorMessage(e));
    }
  }, [aiProvider, aiApiKey, aiModel, aiBaseUrl, addLog]);

  const handleAiSuggestion = useCallback(async (suggestion: AiSuggestion) => {
    const message =
      suggestion.action === "expand_node"
        ? `Expand node "${suggestion.target_id}" and analyze its connections.`
        : suggestion.action === "run_hypothesis"
        ? `Run this hunt hypothesis: ${suggestion.target_id}`
        : suggestion.action === "search_entities"
        ? `Search for entities matching "${suggestion.target_id}"`
        : suggestion.label;
    sendAiMessage(message);
  }, [sendAiMessage]);

  return {
    analyzeAiOpen,
    analyzeAiLoading,
    analyzeAiError,
    analyzeAiQuestion,
    aiConversation,
    aiLastSuggestions,
    aiProvider,
    aiApiKey,
    aiModel,
    aiBaseUrl,
    aiSettingsOpen,
    aiChatEndRef,
    setAnalyzeAiOpen,
    setAnalyzeAiQuestion,
    setAiProvider,
    setAiApiKey,
    setAiModel,
    setAiBaseUrl,
    setAiSettingsOpen,
    sendAiMessage,
    runAnalyzeAi,
    clearAiConversation,
    saveAiProvider,
    handleAiSuggestion,
  };
}
