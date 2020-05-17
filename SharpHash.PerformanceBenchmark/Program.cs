using System;
using System.Collections.Generic;
using System.Text;
using SharpHash.Base;
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Interfaces;

namespace SharpHash.PerformanceBenchmark
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            IHash HashInstance = HashFactory.CreateHash("blake_2S");

            IHashResult result = HashInstance.ComputeString("", Encoding.UTF8);

            Console.WriteLine(result.ToString() + " \n\r");

            return;

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