using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HelloWorld
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            if (args.Length > 0)
            {
                foreach (var arg in args)
                {
                    Console.WriteLine("Arg: " + arg);
                }
            }   
        }
    }
}
