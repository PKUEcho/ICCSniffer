package cn.edu.pku.echo.icc_sniffer.main;

import java.util.regex.Pattern;

public class ConstConfig {
	public static final Pattern interested_string = Pattern.compile("^[a-zA-Z0-9_\\.\\$]+$");
	public static final String[] interested_method = {"startActivity", "startService", "bindService", "sendBroadcast" };
	public static boolean DEBUG = false;
}
