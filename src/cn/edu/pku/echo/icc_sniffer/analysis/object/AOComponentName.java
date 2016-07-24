package cn.edu.pku.echo.icc_sniffer.analysis.object;

public class AOComponentName extends AnalysisObject{
	public String package_name;
	public String activity_name;
	public AOComponentName() {
		package_name = "";
		activity_name = "";
		type = "Landroid/content/ComponentName;";
	}
	
	public AOComponentName(String pn, String an) {
		if (pn == null)
			package_name = "";
		else
			package_name = pn;
		if (an == null)
			activity_name = "";
		else
			activity_name = an;
		type = "Landroid/content/ComponentName;";
	}
	
	@Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((package_name == null) ? 0 :package_name.hashCode());
        result = prime * result + ((activity_name == null) ? 0: activity_name.hashCode());
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
        AOComponentName other = (AOComponentName) obj;
        if (package_name == null) {
            if (other.package_name != null) {
                return false;
            }
        } else if (!package_name.equals(other.package_name)) {
            return false;
        }
        if (activity_name == null) {
            if (other.activity_name != null) {
                return false;
            }
        } else if (!activity_name.equals(other.activity_name)) {
            return false;
        }
        return true;
	}

	@Override
	public AnalysisObject copy() {
		return new AOComponentName(this.package_name, this.activity_name);
	}
}
