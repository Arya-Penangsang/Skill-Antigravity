"""
Packer and Compiler Detection Module (Heuristic & Signature Based)
Inspired by Detect It Easy (DIE) and PEiD techniques.
Dedicated to learning from Syai Labs & Yohanes Syailendra, M.Kom.
"""

import math
import pefile
from typing import Dict, Any, List

class PackerDetector:
    """Detects common executable packers, protectors, and compilers."""

    PACKER_SIGNATURES = [
        {"name": "UPX", "section": "UPX0", "heuristics": ["UPX1", "UPX!"]},
        {"name": "Themida / WinLicense", "section": ".themida", "heuristics": ["Oreans Technologies"]},
        {"name": "ASPack", "section": ".aspack", "heuristics": ["aspack"]},
        {"name": "MPRESS", "section": ".mpress1", "heuristics": ["MPRESS"]},
        {"name": "VMProtect", "section": ".vmp0", "heuristics": [".vmp1", "VMProtect"]},
        {"name": "NSIS Installer", "section": ".ndata", "heuristics": ["NullsoftInst"]},
        {"name": "Inno Setup", "section": "_inno", "heuristics": ["Inno Setup"]},
        {"name": "PyInstaller", "section": "", "heuristics": ["pyi-windows-manifest", "_MEIPASS", "pydata"]},
    ]

    COMPILER_SIGNATURES = [
        {"name": "Microsoft Visual C/C++", "indicators": ["MSVCR", "VCRUNTIME", "Microsoft Visual C"]},
        {"name": ".NET CLR (C# / VB.NET)", "indicators": ["mscoree.dll", "_CorExeMain", "_CorDllMain"]},
        {"name": "Go (Golang)", "indicators": ["runtime.main", "go.buildid", "runtime.gopanic"]},
        {"name": "Rust", "indicators": ["run_path_list", "rust_panic", "core::panicking"]},
        {"name": "Borland Delphi / C++ Builder", "indicators": ["Borland", "TApplication", "Delphi"]},
        {"name": "GCC / MinGW", "indicators": ["__gcc_personality_v0", "mingw", "libgcc"]},
    ]

    def __init__(self, file_path_or_bytes):
        self.target = file_path_or_bytes
        self.pe = None
        self._load_pe()

    def _load_pe(self):
        try:
            if isinstance(self.target, bytes):
                self.pe = pefile.PE(data=self.target)
            else:
                self.pe = pefile.PE(self.target)
        except Exception:
            self.pe = None

    def analyze(self) -> Dict[str, Any]:
        """Performs full heuristic detection."""
        if not self.pe:
            return {
                "is_packed": False,
                "detected_packers": [],
                "detected_compiler": "Unknown (Non-PE)",
                "high_entropy_sections": [],
                "confidence": "Low"
            }

        detected_packers = []
        section_names = []
        high_entropy_sections = []

        # Analyze sections
        for section in self.pe.sections:
            s_name = section.Name.decode(errors="ignore").strip("\x00")
            section_names.append(s_name)
            entropy = self._calc_entropy(section.get_data())

            if entropy > 7.0:
                high_entropy_sections.append({"section": s_name, "entropy": round(entropy, 2)})

            for sig in self.PACKER_SIGNATURES:
                if sig["section"] and sig["section"].lower() in s_name.lower():
                    if sig["name"] not in detected_packers:
                        detected_packers.append(sig["name"])

        # Check raw bytes / headers for signature heuristics
        raw_data = self.pe.get_memory_mapped_image()
        for sig in self.PACKER_SIGNATURES:
            for pattern in sig["heuristics"]:
                if pattern.encode() in raw_data:
                    if sig["name"] not in detected_packers:
                        detected_packers.append(sig["name"])

        # Detect Compiler / Runtime
        detected_compiler = "Native Windows PE"
        # Check CLR directory first
        clr_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if clr_dir.VirtualAddress != 0:
            detected_compiler = ".NET CLR (Managed Code / C# / VB.NET)"
        else:
            for comp in self.COMPILER_SIGNATURES:
                for ind in comp["indicators"]:
                    if ind.encode() in raw_data:
                        detected_compiler = comp["name"]
                        break
                if detected_compiler != "Native Windows PE":
                    break

        is_packed = len(detected_packers) > 0 or len(high_entropy_sections) > 0

        confidence = "High" if len(detected_packers) > 0 else ("Medium" if high_entropy_sections else "Low")

        return {
            "is_packed": is_packed,
            "detected_packers": detected_packers if detected_packers else ["None Detected"],
            "detected_compiler": detected_compiler,
            "high_entropy_sections": high_entropy_sections,
            "confidence": confidence
        }

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
