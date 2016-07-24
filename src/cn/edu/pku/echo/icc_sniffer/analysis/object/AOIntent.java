package cn.edu.pku.echo.icc_sniffer.analysis.object;

public class AOIntent extends AnalysisObject{
	public String action;
	public String categories;
	public String data;
	public AOComponentName component;
	public AOIntent() {
		action = "";
		component = null;
		data = "";
		categories = "";
		type = "Landroid/content/Intent;";
	}
	public AOIntent(String act, AOComponentName cn) {
		action = act;
		categories = "";
		data = "";
		if (cn != null)
			component = (AOComponentName) cn.copy();
		else
			component = null;
	}
	
	@Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + action.hashCode();
        result = prime * result + categories.hashCode();
        result = prime * result + data.hashCode();
        result = prime * result + ((component == null) ? 0 : component.hashCode());
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
        AOIntent other = (AOIntent) obj;
        
        if (!action.equals(other.action)) {
            return false;
        }
        
        if (!categories.equals(other.categories)) {
            return false;
        }
        
        if (!data.equals(other.data)) {
            return false;
        }
        
        if (component == null) {
            if (other.component != null) {
                return false;
            }
        } else if (!component.equals(other.component)) {
            return false;
        }
        return true;
	}

	@Override
	public AnalysisObject copy() {
		return new AOIntent(this.action, this.component);
	}
}
