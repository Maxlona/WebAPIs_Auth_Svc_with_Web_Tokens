using AuthService.AuthModels;
using AuthService.Logic.Workers;
using AuthService.SQL_Models;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Logic.Reset
{
    public class Reset : IReset
    {
        IWorker _worker;
        public Reset(IWorker worker)
        {
            _worker = worker;
        }

        public async Task<bool> ResetUserPassword(ResetModel reset)
        {
            return await _worker.ResetUserPassword(reset);
        }

        public async Task<string> RequestPasswordReset(ResetRequestModel request)
        {
            return await _worker.RequestPasswordReset(request);
        }
    }
}
