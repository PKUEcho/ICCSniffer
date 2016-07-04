package cn.edu.pku.echo.icc_sniffer.analysis;

import com.googlecode.d2j.node.insn.DexStmtNode;

public abstract class AnalysisResult {
	public AnalysisResult() {
	}

	public abstract AnalysisResult merge(DexStmtNode insn);

	public abstract void printResult();

	public abstract boolean covers(AnalysisResult result);

	public abstract void mergeResult(AnalysisResult r);

	public abstract AnalysisResult clone();
	// public abstract static AnalysisResult getInstance();
}