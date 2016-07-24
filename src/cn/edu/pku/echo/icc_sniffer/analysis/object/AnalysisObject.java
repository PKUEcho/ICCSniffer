package cn.edu.pku.echo.icc_sniffer.analysis.object;

public abstract class AnalysisObject {
	public String type;
	public abstract AnalysisObject copy();
}
