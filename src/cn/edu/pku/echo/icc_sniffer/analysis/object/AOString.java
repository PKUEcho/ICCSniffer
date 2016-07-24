package cn.edu.pku.echo.icc_sniffer.analysis.object;

public class AOString extends AnalysisObject{
	public String str;
	public AOString(String s) {
		str = s;
		type = "Ljava/lang/String;";
	}
	
	@Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + str.hashCode();
        return result;
    }
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AOString other = (AOString) obj;
        if (str == null) {
            if (other.str != null) {
                return false;
            }
        } else if (!str.equals(other.str)) {
            return false;
        }
        return true;
	}

	@Override
	public AnalysisObject copy() {
		return new AOString(this.str);
	}
}
