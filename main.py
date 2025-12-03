import customtkinter as ctk
import numpy as np
from sbox_generator import SBoxGenerator
from cryptanalysis import Cryptanalysis
import threading

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AES S-box Generator & Analyzer")
        self.geometry("1100x700")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="S-Box 44", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.generate_btn = ctk.CTkButton(self.sidebar_frame, text="Generate S-box", command=self.generate_sbox)
        self.generate_btn.grid(row=1, column=0, padx=20, pady=10)

        self.analyze_btn = ctk.CTkButton(self.sidebar_frame, text="Analyze", command=self.analyze_sbox, state="disabled")
        self.analyze_btn.grid(row=2, column=0, padx=20, pady=10)

        self.compare_btn = ctk.CTkButton(self.sidebar_frame, text="Compare vs AES", command=self.compare_sbox, state="disabled")
        self.compare_btn.grid(row=3, column=0, padx=20, pady=10)

        # Main Content
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # S-box Grid View
        self.sbox_frame = ctk.CTkScrollableFrame(self.main_frame, label_text="Generated S-box (Hex)")
        self.sbox_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Analysis Results
        self.analysis_frame = ctk.CTkScrollableFrame(self.main_frame, label_text="Cryptanalysis Results")
        self.analysis_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.sbox_labels = []
        self.current_sbox = None

    def generate_sbox(self):
        self.generate_btn.configure(state="disabled")
        
        # Run in thread to not freeze UI
        threading.Thread(target=self._generate_task).start()

    def _generate_task(self):
        gen = SBoxGenerator()
        self.current_sbox = gen.generate()
        
        self.after(0, self._display_sbox)

    def _display_sbox(self):
        # Clear previous
        for widget in self.sbox_frame.winfo_children():
            widget.destroy()
            
        # Display grid 16x16
        for i in range(16):
            for j in range(16):
                val = self.current_sbox[i*16 + j]
                lbl = ctk.CTkLabel(self.sbox_frame, text=f"{val:02X}", width=30, height=30, fg_color="gray20", corner_radius=5)
                lbl.grid(row=i, column=j, padx=2, pady=2)
        
        self.generate_btn.configure(state="normal")
        self.analyze_btn.configure(state="normal")
        self.compare_btn.configure(state="normal")

    def analyze_sbox(self):
        self.analyze_btn.configure(state="disabled")
        self.analysis_frame_clear()
        self.log_analysis("Running analysis... Please wait.")
        
        threading.Thread(target=self._analyze_task).start()

    def analysis_frame_clear(self):
        for widget in self.analysis_frame.winfo_children():
            widget.destroy()

    def log_analysis(self, text, value=None):
        # Helper to add label to analysis frame
        # We need to schedule this on main thread
        self.after(0, lambda: self._add_analysis_label(text, value))

    def _add_analysis_label(self, text, value):
        frame = ctk.CTkFrame(self.analysis_frame)
        frame.pack(fill="x", padx=5, pady=5)
        
        lbl_text = ctk.CTkLabel(frame, text=text, anchor="w")
        lbl_text.pack(side="left", padx=10)
        
        if value is not None:
            lbl_val = ctk.CTkLabel(frame, text=str(value), font=ctk.CTkFont(weight="bold"))
            lbl_val.pack(side="right", padx=10)

    def _analyze_task(self):
        if not self.current_sbox:
            return
            
        crypto = Cryptanalysis(self.current_sbox)
        
        # Permutation Check
        is_perm = crypto.is_permutation()
        self.log_analysis("Is Permutation:", "Yes" if is_perm else "No")
        
        # NL
        nl = crypto.nonlinearity()
        self.log_analysis("Nonlinearity (NL):", nl)
        
        # SAC
        sac = crypto.strict_avalanche_criterion()
        self.log_analysis("SAC:", f"{sac:.5f}")
        
        # BIC
        bic = crypto.bit_independence_criterion()
        self.log_analysis("BIC-NL:", f"{bic:.2f}")
        
        # LAP
        lap = crypto.linear_approximation_probability()
        self.log_analysis("LAP:", f"{lap:.5f}")
        
        # DAP
        dap = crypto.differential_approximation_probability()
        self.log_analysis("DAP:", f"{dap:.5f}")
        
        # DU
        du = crypto.differential_uniformity()
        self.log_analysis("Diff. Uniformity (DU):", du)
        
        # AD
        ad = crypto.algebraic_degree()
        self.log_analysis("Algebraic Degree (AD):", ad)
        
        # CI
        ci = crypto.correlation_immunity()
        self.log_analysis("Correlation Immunity (CI):", ci)
        
        self.after(0, lambda: self.analyze_btn.configure(state="normal"))

    def compare_sbox(self):
        # Create a new window for comparison
        comp_window = ctk.CTkToplevel(self)
        comp_window.title("Comparison with Standard AES S-box")
        comp_window.geometry("800x600")
        
        # Standard AES S-box (Hardcoded for reliability)
        aes_sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        
        # UI for comparison
        frame = ctk.CTkScrollableFrame(comp_window, label_text="Comparison Results")
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Headers
        headers = ["Metric", "Generated S-box", "Standard AES S-box"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(frame, text=h, font=ctk.CTkFont(weight="bold")).grid(row=0, column=i, padx=10, pady=5)
            
        # Metrics to compare
        metrics = [
            ("Is Permutation", lambda c: "Yes" if c.is_permutation() else "No"),
            ("Nonlinearity (NL)", lambda c: c.nonlinearity()),
            ("SAC", lambda c: f"{c.strict_avalanche_criterion():.5f}"),
            ("BIC-NL", lambda c: f"{c.bit_independence_criterion():.2f}"),
            ("LAP", lambda c: f"{c.linear_approximation_probability():.5f}"),
            ("DAP", lambda c: f"{c.differential_approximation_probability():.5f}"),
            ("Diff. Uniformity", lambda c: c.differential_uniformity()),
            ("Algebraic Degree", lambda c: c.algebraic_degree()),
            ("Correlation Immunity", lambda c: c.correlation_immunity())
        ]
        
        # Run analysis for both
        if not self.current_sbox:
            ctk.CTkLabel(frame, text="Please generate S-box first.").grid(row=1, column=0, columnspan=3)
            return

        crypto_gen = Cryptanalysis(self.current_sbox)
        crypto_aes = Cryptanalysis(aes_sbox)
        
        for i, (name, func) in enumerate(metrics):
            row = i + 1
            ctk.CTkLabel(frame, text=name).grid(row=row, column=0, padx=10, pady=2, sticky="w")
            
            # Generated
            try:
                val_gen = func(crypto_gen)
            except Exception as e:
                val_gen = "Error"
            ctk.CTkLabel(frame, text=str(val_gen)).grid(row=row, column=1, padx=10, pady=2)
            
            # AES
            try:
                val_aes = func(crypto_aes)
            except Exception as e:
                val_aes = "Error"
            ctk.CTkLabel(frame, text=str(val_aes)).grid(row=row, column=2, padx=10, pady=2)

if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    app = App()
    app.mainloop()
