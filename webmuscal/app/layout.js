
import "./globals.css";
import { FoodProvider } from "./context";

export const metadata = {
  title: "/Webmuscal.KMITL",
  description: "Generated by create next app",
};
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <div className={`max-[1399px]:hidden min-[1791px]:hidden absolute z-10`}>
          <FoodProvider>
            {children}
          </FoodProvider>
         </div>
         <div className=" w-[100vw] h-[100vh] bg-bb1 flex flex-col justify-center items-center">
            <div className="text-[#ffff] text-[20px] min-[1790px]:text-[100px] animate-pulse">Please use a screen</div>
            <div className="text-[#ffff] text-[20px] min-[1790px]:text-[100px] animate-pulse">width of 1400px-1790px.</div>
         </div>
      </body>
    </html>
  );
}
