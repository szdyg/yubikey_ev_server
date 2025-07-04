using System;
using Nancy;
using Nancy.Hosting.Self;

namespace yubikey_ev_server
{
    public class SignModule : NancyModule
    {
        public SignModule()
        {
            Get("/sign", _ =>
            {
                if (!Request.Query.path.HasValue ||
                    !Request.Query.thumbprint.HasValue ||
                    !Request.Query.timestamp.HasValue)
                {
                    return HttpStatusCode.BadRequest;
                }

                string path = Request.Query.path;
                string thumbprint = Request.Query.thumbprint;
                string timestamp = Request.Query.timestamp;

                Console.WriteLine("req for path = " + path);
                Console.WriteLine("thumbprint = " + thumbprint);
                Console.WriteLine("timestamp = " + timestamp);

                string err;
                CodeSign.Sign(path, thumbprint.ToUpper(), timestamp, out err);
                Console.WriteLine("sign err = " + err);
                return Response.AsJson(new
                {
                    Error = err
                });
            });
        }
    }

    internal class Program
    {
        private static void Main(string[] args)
        {
            var uri = new Uri("http://127.0.0.1:11451");
            using (var host = new NancyHost(uri))
            {
                host.Start();
                Console.WriteLine("yubikey_ev_server running on " + uri);
                string input;
                do
                {
                    Console.WriteLine("Type 'exit' to stop the server...");
                    input = Console.ReadLine();
                } while (input?.ToLower() != "exit");

                Console.WriteLine("Stopping server...");
            }
        }
    }
}