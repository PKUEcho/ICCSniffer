package cn.edu.pku.echo.icc_sniffer.main;

public class Main {
	public static void main(String[] args) {
		System.out.println("###### Icc-Sniffer starts ######");
		String pkg = "apps/com.tencent.mm.apk";
		if (args.length < 1) {
			System.out.println("No args to specify apk path!");
//			System.exit(0);
		}
		else
			pkg = args[0];
		APKContainer apk_container = new APKContainer(pkg);
		apk_container.execute(3);
	}
}