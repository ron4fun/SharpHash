using System;
using System.Collections.Generic;

namespace SharpHash.PerformanceBenchmark
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            List<string> stringList = new List<string>();

            Console.WriteLine("Please be patient, this might take some time \n\r");

            try
            {
                PerformanceBenchmark.DoBenchmark(ref stringList);

                foreach (var log in stringList)
                    Console.WriteLine(log);

                Console.WriteLine("\n\rPerformance Benchmark Finished");

                Console.ReadLine();
            }
            catch (Exception e)
            {
                Console.WriteLine($"{e.ToString()} : {e.Message}");
            }
        }
    }
}