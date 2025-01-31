using System.Security.Claims;

namespace System.Linq
{
    internal class SystemCore_EnumerableDebugView<T>
    {
        private IEnumerable<Claim> specificClaims;

        public SystemCore_EnumerableDebugView(IEnumerable<Claim> specificClaims)
        {
            this.specificClaims = specificClaims;
        }
    }
}